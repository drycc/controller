import logging

from datetime import datetime
from django.utils import timezone
from django.conf import settings
from django.db import models
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.db.models import F, Func, Value, JSONField
from api.tasks import run_pipeline
from api.exceptions import DryccException, AlreadyExists
from scheduler import KubeHTTPException
from scheduler.resources.pod import DEFAULT_CONTAINER_PORT

from ..utils import CacheLock, DeployLock

from .base import UuidAuditedModel
from .appsettings import AppSettings


User = get_user_model()
logger = logging.getLogger(__name__)


class Release(UuidAuditedModel):
    """
    Software release deployed by the application platform

    Releases contain a :class:`Build` and a :class:`Config`.
    """
    STATE_CHOICES = (
        ("created", "Release created but not deployed"),
        ("crashed", "Release pipeline runtime crashed"),
        ("succeed", "Release pipeline runtime succeed"),
    )
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    state = models.TextField(choices=STATE_CHOICES, default=STATE_CHOICES[0][0])
    version = models.PositiveIntegerField()
    summary = models.TextField(blank=True, null=True)
    failed = models.BooleanField(default=False)
    exception = models.TextField(blank=True, null=True)
    conditions = models.JSONField(default=list)
    deployed_ptypes = models.JSONField(default=list)

    config = models.ForeignKey('Config', on_delete=models.CASCADE)
    build = models.ForeignKey('Build', null=True, on_delete=models.CASCADE)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'version'),)

    def __str__(self):
        return "{0}-{1}".format(self.app.id, self.version_name)

    @property
    def ptypes(self):
        if self.build is not None:
            return self.build.ptypes
        return []

    @property
    def version_name(self):
        return f'v{self.version}'

    def get_runners(self, ptypes):
        results = []
        ptypes = self.ptypes if not ptypes else ptypes
        for run in self.build.dryccfile.get('run', []):
            for ptype in ptypes:
                when_ptypes = run.get('when', {}).get('ptypes', [])
                if not when_ptypes or ptype in when_ptypes:
                    image = run.get('image', self.build.get_image(ptype))
                    results.append({
                        'image': self.build.get_image(image, default_image=image),
                        'args': run.get('args', []),
                        'command': run.get('command', []),
                        'timeout': run.get('timeout', settings.DRYCC_PILELINE_RUN_TIMEOUT),
                    })
                    break
        return results

    def add_condition(self, **kwargs):
        if "created" not in kwargs:
            kwargs["created"] = datetime.now(timezone.utc).strftime(settings.DRYCC_DATETIME_FORMAT)
        type(self).objects.filter(pk=self.pk).update(
            conditions=Func(
                F("conditions"),
                Value(["0"]),
                Value(kwargs, JSONField()),
                function="jsonb_insert",
            )
        )

    def get_deploy_image(self, ptype):
        """
        In the deploy phase of dryccfile
        Return the kubernetes "container image" to be sent off to the scheduler.
        """
        image = self.build.dryccfile.get('deploy', {}).get(ptype, {}).get(
            'image', self.build.get_image(ptype))
        return self.build.get_image(image, default_image=image)

    def get_deploy_args(self, ptype):
        """
        In the deploy phase of dryccfile
        Return the kubernetes "container arguments" to be sent off to the scheduler.
        """
        if self.build is not None:
            if self.build.dryccfile:
                return self.build.dryccfile['deploy'].get(ptype, {}).get('args', [])
            else:
                # dockerfile or container image
                if self.build.dockerfile or not self.build.sha:
                    # has profile
                    if self.build.procfile and ptype in self.build.procfile:
                        args = self.build.procfile[ptype]
                        return args.split()
        return []

    def get_deploy_command(self, ptype):
        """
        In the deploy phase of dryccfile
        Return the kubernetes "container command" to be sent off to the scheduler.
        """
        return self.build.dryccfile.get(
            'deploy', {}).get(ptype, {}).get('command', [])

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this application.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.app.id, message))

    def new(self, user, config, build, summary=None):
        """
        Create a new application release using the provided Build and Config
        on behalf of a user.

        Releases start at v1 and auto-increment.
        """
        # construct fully-qualified target image
        new_version = self.app.release_set.latest().version + 1
        # create new release and auto-increment version
        return Release.objects.create(
            owner=user, app=self.app, config=config,
            build=build, version=new_version, summary=summary
        )

    def get_port(self, ptype):
        """
        Get application port for a given release. If pulling from private registry
        then use default port or read from ENV var, otherwise attempt to pull from
        the container image
        """
        return int(self.config.typed_values.get(
            ptype, {}).get(
                'PORT', self.config.values.get('PORT', DEFAULT_CONTAINER_PORT)))

    def deploy(self, ptypes=None, force_deploy=False):
        msg = 'there is an executing pipeline, please wait or force deploy'
        # change deployed_ptypes lock
        lock = CacheLock("release:%s" % self.pk)
        try:
            if lock.acquire() or force_deploy:
                if ptypes is None:
                    deployed_ptypes = self.ptypes
                else:
                    deployed_ptypes = list(set(self.deployed_ptypes).union(ptypes))
                type(self).objects.filter(pk=self.pk).update(deployed_ptypes=deployed_ptypes)
            else:
                raise DryccException(msg)
        finally:
            lock.release()
        # deploy lock
        if not DeployLock(self.app.pk).acquire(ptypes, force=force_deploy):
            raise DryccException(msg)
        run_pipeline.delay(self, ptypes, force_deploy)

    def previous(self):
        """
        Return the previous Release to this one.

        :return: the previous :class:`Release`, or None
        """
        releases = self.app.release_set
        if self.pk:
            releases = releases.exclude(pk=self.pk)

        q = Q(failed=False, state="succeed")
        try:
            app_settings = self.app.appsettings_set.latest()
            if app_settings.autorollback is False:
                q = Q(state__in=["crashed", "succeed"])
        except AppSettings.DoesNotExist:
            pass
        try:
            # Get the Release previous to this one
            prev_release = releases.filter(q).latest()
        except Release.DoesNotExist:
            prev_release = None
        return prev_release

    def rollback(self, user, ptypes=None, version=None):
        try:
            # if no version is provided then grab version from object
            version = (self.version - 1) if version is None else int(version)

            if version < 1:
                raise DryccException('version cannot be below 0')
            elif version == 1:
                raise DryccException('Cannot roll back to initial release.')
            prev = self.app.release_set.get(version=version)
            if prev.failed:
                raise DryccException('Cannot roll back to failed release.')
            latest_version = self.app.release_set.latest().version
            new_release = self.new(
                user,
                build=prev.build,
                config=prev.config,
                summary="{} rolled back to v{}".format(user, version),
            )
            if self.build is not None:
                new_release.deploy(ptypes, force_deploy=True)
            return new_release
        except Exception as e:
            # check if the exception is during create or publish
            if ('new_release' not in locals() and 'latest_version' in locals() and
                    self.app.release_set.latest().version == latest_version+1):
                new_release = self.app.release_set.latest()
                new_release.state = "crashed"
                new_release.failed = True
                if new_release.summary:
                    new_release.summary += " "
                new_release.summary += "{} performed roll back to a release that failed".format(
                    self.owner)
                # Get the exception that has occured
                new_release.exception = "error: {}".format(str(e))
                # avoid overwriting other fields
                new_release.save(update_fields=["state", "failed", "summary", "exception"])
            raise DryccException(str(e)) from e

    def cleanup_old(self, ptypes=None):
        """
        Cleanup any old resources from Kubernetes

        This includes any RSs that are no longer considered the latest release (just a safety net)
        Secrets no longer tied to any ReplicaSet
        Stray pods no longer relevant to the latest release
        """
        self.log(
            'Cleaning up RSs for releases older than {} (latest)'.format(self.version_name),
            level=logging.DEBUG
        )
        # base labels
        labels = {'heritage': 'drycc'}
        if ptypes is not None:
            labels['type__in'] = ptypes
        # Cleanup controllers
        replica_sets_removal = []
        replica_sets = self.scheduler().rs.get(self.app.id, labels=labels).json()['items']
        if not replica_sets:
            replica_sets = []
        for replica_set in replica_sets:
            current_version_name = replica_set['metadata']['labels']['version']
            # skip the latest release
            if current_version_name == self.version_name:
                continue

            # aggregate versions together to removal all at once
            if current_version_name not in replica_sets_removal:
                replica_sets_removal.append(current_version_name)

        if replica_sets_removal:
            self.log(
                'Found the following versions to cleanup: {}'.format(
                    ', '.join(replica_sets_removal)),
                level=logging.DEBUG
            )
        # this is RC related
        for version_name in replica_sets_removal:
            self._delete_release_in_scheduler(self.app.id, ptypes, version_name)
        # handle Deployments specific cleanups
        self._cleanup_deployment_secrets_and_configs(self.app.id, ptypes)
        # Remove stray pods
        self._cleanup_stray_pods(self.app.id, ptypes, self.version_name)

    def _cleanup_stray_pods(self, namespace, ptypes, latest_version_name):
        labels = {'heritage': 'drycc'}
        if ptypes is not None:
            labels['type__in'] = ptypes
        pods = self.scheduler().pod.get(namespace, labels=labels).json()['items']
        if not pods:
            pods = []
        for pod in pods:
            if self.scheduler().pod.deleted(pod):
                continue

            current_version_name = pod['metadata']['labels']['version']
            # skip the latest release
            if current_version_name == latest_version_name:
                continue

            try:
                self.scheduler().pod.delete(namespace, pod['metadata']['name'])
            except KubeHTTPException as e:
                # Sometimes k8s will manage to remove the pod from under us
                if e.response.status_code == 404:
                    continue

    def _cleanup_deployment_secrets_and_configs(self, namespace, ptypes=None):
        """
        Clean up any environment secrets (and in the future ConfigMaps) that
        are tied to a release Deployments no longer track

        This is done by checking the available ReplicaSets and only removing
        objects not attached to anything. This will allow releases done outside
        of Drycc Controller
        """

        # Find all ReplicaSets
        version_names = [self.version_name, ]
        labels = {'heritage': 'drycc', 'app': namespace}
        replicasets = self.scheduler().rs.get(namespace, labels=labels).json()['items']
        if not replicasets:
            replicasets = []
        for replicaset in replicasets:
            if (
                'version' not in replicaset['metadata']['labels'] or
                replicaset['metadata']['labels']['version'] in version_names
            ):
                continue

            version_names.append(replicaset['metadata']['labels']['version'])

        # find all env secrets not owned by any replicaset
        labels = {
            'heritage': 'drycc',
            'app': namespace,
            'class': 'env',
            # http://kubernetes.io/docs/user-guide/labels/#set-based-requirement
            'version__notin': version_names
        }
        if ptypes is not None:
            labels['type__in'] = ptypes
        self.log('Cleaning up orphaned env var secrets for application {}'.format(namespace), level=logging.DEBUG)  # noqa
        secrets = self.scheduler().secret.get(namespace, labels=labels).json()['items']
        if not secrets:
            secrets = []
        for secret in secrets:
            self.scheduler().secret.delete(namespace, secret['metadata']['name'])

    def _delete_release_in_scheduler(self, namespace, ptypes, version_name):
        """
        Deletes a specific release in k8s based on ReplicationController

        Scale RSs to 0 then delete RSs and the version specific
        secret that container the env var
        """
        labels = {
            'heritage': 'drycc',
            'app': namespace,
            'version': version_name
        }
        if ptypes is not None:
            labels['type__in'] = ptypes
        # see if the app config has deploy timeout preference, otherwise use global
        timeout = self.config.values.get('DRYCC_DEPLOY_TIMEOUT', settings.DRYCC_DEPLOY_TIMEOUT)

        replica_sets = self.scheduler().rs.get(namespace, labels=labels).json()['items']
        if not replica_sets:
            replica_sets = []
        for replica_set in replica_sets:
            # Deployment takes care of this in the API, RS does not
            # Have the RS scale down pods and delete itself
            try:
                self.scheduler().rs.scale(namespace, replica_set['metadata']['name'], 0, timeout)
                self.scheduler().rs.delete(namespace, replica_set['metadata']['name'])
            except KubeHTTPException as e:
                if e.response.status_code != 404:
                    raise

    def save(self, *args, **kwargs):  # noqa
        if not self.summary:
            self.summary = ''
            prev_release = self.previous()
            # compare this build to the previous build
            old_build = prev_release.build if prev_release else None
            old_config = prev_release.config if prev_release else None
            # if the build changed, log it and who pushed it
            if self.version == 1:
                self.summary += "{} created initial release".format(self.app.owner)
            elif self.build != old_build:
                if self.build.sha:
                    self.summary += "{} deployed {}".format(self.build.owner, self.build.sha[:7])
                else:
                    self.summary += "{} deployed {}".format(self.build.owner, self.build.image)
            elif self.config != old_config:
                for field, diff in self.config.diff(old_config).items():
                    diff_list = []
                    for diff_type, values in diff.items():
                        diff_list.append(f'{diff_type} {field} {", ".join(values.keys())}')
                    if diff_list:
                        changes = ', '.join(diff_list)
                        self.summary += "{} {}".format(self.config.owner, changes)
            if not self.summary:
                if self.version == 1:
                    self.summary = "{} created the initial release".format(self.owner)
                else:
                    # There were no changes to this release
                    raise AlreadyExists("{} changed nothing - release stopped".format(self.owner))
        super(Release, self).save(*args, **kwargs)
