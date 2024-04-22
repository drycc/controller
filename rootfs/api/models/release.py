import logging

from django.conf import settings
from django.db import models
from django.contrib.auth import get_user_model
from api.tasks import run_pipeline
from api.exceptions import DryccException, AlreadyExists
from scheduler import KubeHTTPException
from scheduler.resources.pod import DEFAULT_CONTAINER_PORT
from .base import UuidAuditedModel


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
    canary = models.BooleanField(default=False)
    exception = models.TextField(blank=True, null=True)

    config = models.ForeignKey('Config', on_delete=models.CASCADE)
    build = models.ForeignKey('Build', null=True, on_delete=models.CASCADE)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'version'),)

    def __str__(self):
        return "{0}-v{1}".format(self.app.id, self.version)

    @property
    def procfile_types(self):
        if self.build is not None:
            return self.build.procfile_types
        return []

    def get_run_image(self):
        """
        In the run phase of dryccfile
        Return the kubernetes "container image" to be sent off to the scheduler.
        """
        image = self.build.dryccfile.get('run', {}).get(
            'image', self.build.get_image('run'))
        return self.build.get_image(image, default_image=image)

    def get_run_args(self):
        """
        In the run phase of dryccfile
        Return the kubernetes "container arguments" to be sent off to the scheduler.
        """
        return self.build.dryccfile.get('run', {}).get('args', [])

    def get_run_command(self):
        """
        In the run phase of dryccfile
        Return the kubernetes "container command" to be sent off to the scheduler.
        """
        return self.build.dryccfile.get('run', {}).get('command', [])

    def get_deploy_image(self, container_type):
        """
        In the deploy phase of dryccfile
        Return the kubernetes "container image" to be sent off to the scheduler.
        """
        image = self.build.dryccfile.get('deploy', {}).get(container_type, {}).get(
            'image', self.build.get_image(container_type))
        return self.build.get_image(image, default_image=image)

    def get_deploy_args(self, container_type):
        """
        In the deploy phase of dryccfile
        Return the kubernetes "container arguments" to be sent off to the scheduler.
        """
        if self.build is not None:
            if self.build.dryccfile:
                return self.build.dryccfile['deploy'].get(container_type, {}).get('args', [])
            else:
                # dockerfile or container image
                if self.build.dockerfile or not self.build.sha:
                    # has profile
                    if self.build.procfile and container_type in self.build.procfile:
                        args = self.build.procfile[container_type]
                        return args.split()
        return []

    def get_deploy_command(self, container_type):
        """
        In the deploy phase of dryccfile
        Return the kubernetes "container command" to be sent off to the scheduler.
        """
        return self.build.dryccfile.get(
            'deploy', {}).get(container_type, {}).get('command', [])

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this application.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.app.id, message))

    def new(self, user, config, build, summary=None, canary=False):
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
            build=build, version=new_version, summary=summary, canary=canary
        )

    def get_port(self):
        """
        Get application port for a given release. If pulling from private registry
        then use default port or read from ENV var, otherwise attempt to pull from
        the container image
        """
        try:
            envs = self.config.values
            creds = self.get_registry_auth()

            if self.build.type == "buildpack":
                self.log(
                    'buildpack type detected. Defaulting to $PORT %s' % DEFAULT_CONTAINER_PORT)
                return DEFAULT_CONTAINER_PORT

            # application has registry auth - $PORT is required
            if (creds is not None) or (settings.REGISTRY_LOCATION != 'on-cluster'):
                if envs.get('PORT', None) is None:
                    if not self.app.appsettings_set.latest().routable:
                        return None
                    raise DryccException(
                        'PORT needs to be set in the application config '
                        'when using a private registry'
                    )

                # User provided PORT
                return int(envs.get('PORT'))

            # If the user provides PORT
            return int(envs.get('PORT', DEFAULT_CONTAINER_PORT))

        except Exception as e:
            raise DryccException(str(e)) from e

    def get_registry_auth(self):
        """
        Gather login information for private registry if needed
        """
        auth = None
        registry = self.config.registry
        if registry.get('username', None):
            auth = {
                'username': registry.get('username', None),
                'password': registry.get('password', None),
                'email': self.owner.email
            }

        return auth

    def previous(self):
        """
        Return the previous Release to this one.

        :return: the previous :class:`Release`, or None
        """
        releases = self.app.release_set
        if self.pk:
            releases = releases.exclude(pk=self.pk)

        try:
            # Get the Release previous to this one
            prev_release = releases.filter(failed=False).latest()
        except Release.DoesNotExist:
            prev_release = None
        return prev_release

    def rollback(self, user, version=None):
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
            app_settings = self.app.appsettings_set.latest()
            latest_version = self.app.release_set.latest().version
            new_release = self.new(
                user,
                build=prev.build,
                config=prev.config,
                summary="{} rolled back to v{}".format(user, version),
                canary=len(app_settings.canaries) > 0,
            )

            if self.build is not None:
                run_pipeline.delay(new_release, force_deploy=True)
            return new_release
        except Exception as e:
            # check if the exception is during create or publish
            if ('new_release' not in locals() and 'latest_version' in locals() and
                    self.app.release_set.latest().version == latest_version+1):
                new_release = self.app.release_set.latest()
                new_release.state = "crashed"
                new_release.failed = True
                new_release.summary = "{} performed roll back to a release that failed".format(self.owner)  # noqa
                # Get the exception that has occured
                new_release.exception = "error: {}".format(str(e))
                new_release.save()
            raise DryccException(str(e)) from e

    def cleanup_old(self):  # noqa
        """
        Cleanup any old resources from Kubernetes

        This includes any RSs that are no longer considered the latest release (just a safety net)
        Secrets no longer tied to any ReplicaSet
        Stray pods no longer relevant to the latest release
        """
        latest_version = 'v{}'.format(self.version)
        self.log(
            'Cleaning up RSs for releases older than {} (latest)'.format(latest_version),
            level=logging.DEBUG
        )

        # Cleanup controllers
        labels = {'heritage': 'drycc'}
        replica_sets_removal = []
        replica_sets = self.scheduler().rs.get(self.app.id, labels=labels).json()['items']
        if not replica_sets:
            replica_sets = []
        for replica_set in replica_sets:
            current_version = replica_set['metadata']['labels']['version']
            # skip the latest release
            if current_version == latest_version:
                continue

            # aggregate versions together to removal all at once
            if current_version not in replica_sets_removal:
                replica_sets_removal.append(current_version)

        if replica_sets_removal:
            self.log(
                'Found the following versions to cleanup: {}'.format(', '.join(replica_sets_removal)),  # noqa
                level=logging.DEBUG
            )

        # this is RC related
        for version in replica_sets_removal:
            self._delete_release_in_scheduler(self.app.id, version)

        # handle Deployments specific cleanups
        self._cleanup_deployment_secrets_and_configs(self.app.id)

        # Remove stray pods
        labels = {'heritage': 'drycc'}
        pods = self.scheduler().pod.get(self.app.id, labels=labels).json()['items']
        if not pods:
            pods = []
        for pod in pods:
            if self.scheduler().pod.deleted(pod):
                continue

            current_version = pod['metadata']['labels']['version']
            # skip the latest release
            if current_version == latest_version:
                continue

            try:
                self.scheduler().pod.delete(self.app.id, pod['metadata']['name'])
            except KubeHTTPException as e:
                # Sometimes k8s will manage to remove the pod from under us
                if e.response.status_code == 404:
                    continue

    def _cleanup_deployment_secrets_and_configs(self, namespace):
        """
        Clean up any environment secrets (and in the future ConfigMaps) that
        are tied to a release Deployments no longer track

        This is done by checking the available ReplicaSets and only removing
        objects not attached to anything. This will allow releases done outside
        of Drycc Controller
        """

        # Find all ReplicaSets
        versions = []
        labels = {'heritage': 'drycc', 'app': namespace}
        replicasets = self.scheduler().rs.get(namespace, labels=labels).json()['items']
        if not replicasets:
            replicasets = []
        for replicaset in replicasets:
            if (
                'version' not in replicaset['metadata']['labels'] or
                replicaset['metadata']['labels']['version'] in versions
            ):
                continue

            versions.append(replicaset['metadata']['labels']['version'])

        # find all env secrets not owned by any replicaset
        labels = {
            'heritage': 'drycc',
            'app': namespace,
            'type': 'env',
            # http://kubernetes.io/docs/user-guide/labels/#set-based-requirement
            'version__notin': versions
        }
        self.log('Cleaning up orphaned env var secrets for application {}'.format(namespace), level=logging.DEBUG)  # noqa
        secrets = self.scheduler().secret.get(namespace, labels=labels).json()['items']
        if not secrets:
            secrets = []
        for secret in secrets:
            self.scheduler().secret.delete(namespace, secret['metadata']['name'])

    def _delete_release_in_scheduler(self, namespace, version):
        """
        Deletes a specific release in k8s based on ReplicationController

        Scale RSs to 0 then delete RSs and the version specific
        secret that container the env var
        """
        labels = {
            'heritage': 'drycc',
            'app': namespace,
            'version': version
        }

        # see if the app config has deploy timeout preference, otherwise use global
        timeout = self.config.values.get('DRYCC_DEPLOY_TIMEOUT', settings.DRYCC_DEPLOY_TIMEOUT)

        replica_sets = self.scheduler().rs.get(namespace, labels=labels).json()['items']
        if not replica_sets:
            replica_sets = []
        for replica_set in replica_sets:
            # Deployment takes care of this in the API, RS does not
            # Have the RS scale down pods and delete itself
            self.scheduler().rs.scale(namespace, replica_set['metadata']['name'], 0, timeout)
            self.scheduler().rs.delete(namespace, replica_set['metadata']['name'])

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
