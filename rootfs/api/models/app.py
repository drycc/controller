import base64
import functools
import json
import logging
import random
import re
import requests
import string
import time
import socket
from contextlib import closing
from urllib.parse import urljoin
from collections import OrderedDict, namedtuple
from datetime import datetime, timezone

from docker import auth as docker_auth
from django.conf import settings
from django.db import models
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError, NotFound

from api.utils import get_session
from api.exceptions import AlreadyExists, DryccException, ServiceUnavailable
from api.utils import DeployLock, generate_app_name, apply_tasks
from scheduler import KubeHTTPException, KubeException
from .gateway import Gateway, Route
from .limit import LimitPlan
from .config import Config
from .service import Service
from .release import Release
from .tls import TLS
from .appsettings import AppSettings
from .volume import Volume
from .base import UuidAuditedModel, PTYPE_WEB, PTYPE_RUN, DEFAULT_HTTP_PORT

User = get_user_model()
logger = logging.getLogger(__name__)
AppPermission = namedtuple('AppPermission', ['shortname', 'codename', 'description'])
VIEW_APP_PERMISSION = AppPermission("view", "view_app", "can view app")
CHANGE_APP_PERMISSION = AppPermission("change", "change_app", "can change app")
DELETE_APP_PERMISSION = AppPermission("delete", "delete_app", "can delete app")


class AppPermissionRegistry(object):

    def __init__(self):
        self.tags = {}
        self.permissions = set()

    def get(self, q):
        permissions = [
            permission for permission in self.permissions
            if q == permission.shortname or q == permission.codename
        ]
        permissions.extend([
            permission for permission in self.permissions
            if permission in self.tags and q in self.tags[permission]
        ])
        return permissions[0] if permissions else None

    def register(self, permission, tags=None):
        if tags:
            self.tags[permission] = tags
        self.permissions.add(permission)

    @property
    def codenames(self):
        return [permission[1] for permission in self.permissions]

    @property
    def shortnames(self):
        return [permission[0] for permission in self.permissions]


app_permission_registry = AppPermissionRegistry()
app_permission_registry.register(VIEW_APP_PERMISSION, ["GET", "HEAD", "OPTION"])
app_permission_registry.register(CHANGE_APP_PERMISSION, ["POST", "PUT", "PATCH"])
app_permission_registry.register(DELETE_APP_PERMISSION, ["DELETE"])


# http://kubernetes.io/v1.1/docs/design/identifiers.html
def validate_app_id(value):
    """
    Check that the value follows the kubernetes name constraints
    """
    match = re.match(r'[a-z]([a-z0-9-]*[a-z0-9])?$', value)
    if not match:
        raise ValidationError("App name must start with an alphabetic character, cannot end with a"
                              + " hyphen and can only contain a-z (lowercase), 0-9 and hyphens.")


def validate_app_structure(value):
    """Error if the dict values aren't ints >= 0"""
    try:
        if any(int(v) < 0 for v in value.values()):
            raise ValueError("Must be greater than or equal to zero")
    except ValueError as err:
        raise ValidationError(str(err))


def validate_reserved_names(value):
    """A value cannot use some reserved names."""
    if value in settings.DRYCC_RESERVED_NAMES:
        raise ValidationError('{} is a reserved name.'.format(value))


class App(UuidAuditedModel):
    """
    Application used to service requests on behalf of end-users
    """

    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    id = models.SlugField(max_length=63, unique=True, null=True,
                          validators=[validate_app_id,
                                      validate_reserved_names])
    structure = models.JSONField(
        default=dict, blank=True, validators=[validate_app_structure])

    class Meta:
        verbose_name = 'Application'
        ordering = ['id']

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_app_name()
            while App.objects.filter(id=self.id).exists():
                self.id = generate_app_name()

        # verify the application name doesn't exist as a k8s namespace
        # only check for it if there have been on releases
        try:
            self.release_set.latest()
        except Release.DoesNotExist:
            try:
                if self.scheduler().ns.get(self.id).status_code == 200:
                    # Namespace already exists
                    err = "{} already exists as a namespace in this kuberenetes setup".format(self.id)  # noqa
                    self.log(err, logging.INFO)
                    raise AlreadyExists(err)
            except KubeHTTPException:
                pass

        application = super(App, self).save(**kwargs)

        # create all the required resources
        self.create(*args, **kwargs)

        return application

    @property
    def ptypes(self):
        return list(self.structure.keys())

    def check_ptypes(self, ptypes: set):
        """
        check available procfile types
        """
        if not ptypes:
            ptypes = self.ptypes
        else:
            invalid_ptypes = ptypes.difference(self.ptypes)
            if len(invalid_ptypes) != 0:
                raise DryccException("process type {} is not included in procfile".
                                     format(','.join(invalid_ptypes)))
        return ptypes

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this application.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.id, message))

    def create(self, *args, **kwargs):  # noqa
        """
        Create a application with an initial config, settings, release, domain
        and k8s resource if needed
        """
        cfg = self._set_default_config()
        # Only create if no release can be found
        try:
            self.release_set.latest()
        except Release.DoesNotExist:
            Release.objects.create(
                version=1, owner=self.owner, app=self,
                config=cfg, build=None
            )

        # create required minimum resources in k8s for the application
        namespace = self.id
        self.log('creating Namespace {} and services'.format(namespace), level=logging.DEBUG)
        # Create essential resources
        try:
            self.scheduler().ns.get(namespace)
        except KubeException:
            try:
                self.scheduler().ns.create(namespace)
            except KubeException as e:
                raise ServiceUnavailable('Could not create the Namespace in Kubernetes') from e
        try:
            self.appsettings_set.latest()
        except AppSettings.DoesNotExist:
            AppSettings.objects.create(
                owner=self.owner, app=self, routable=True, autodeploy=True, autorollback=True)
        try:
            self.tls_set.latest()
        except TLS.DoesNotExist:
            TLS.objects.create(owner=self.owner, app=self)

    def delete(self, *args, **kwargs):
        """Delete this application including all containers"""
        self.log("deleting environment")
        try:
            # check if namespace exists
            self.scheduler().ns.get(self.id)

            try:
                self.scheduler().ns.delete(self.id)

                # wait 30 seconds for termination
                for _ in range(30):
                    try:
                        self.scheduler().ns.get(self.id)
                    except KubeHTTPException as e:
                        # only break out on a 404
                        if e.response.status_code == 404:
                            break
            except KubeException as e:
                raise ServiceUnavailable(
                    'Could not delete Kubernetes Namespace {} within 30 seconds'.format(self.id)) from e  # noqa
        except KubeHTTPException:
            # it's fine if the namespace does not exist - delete app from the DB
            pass

        self._clean_app_logs()
        return super(App, self).delete(*args, **kwargs)

    def restart(self, **kwargs):  # noqa
        """
         Restart deployments with the kubectl rollout api
        """
        deployments = []
        if self.structure[kwargs['type']] > 0:
            deployments.append(self._get_job_id(kwargs['type']))
        try:
            tasks = [
                functools.partial(
                    self.scheduler().deployment.restart,
                    self.id,
                    deployment
                ) for deployment in deployments
            ]
            apply_tasks(tasks)
        except Exception as e:
            err = "warning, some pods failed to restart:\n{}".format(str(e))
            self.log(err, logging.WARNING)

    def scale(self, user, structure):
        err_msg = None
        release = self.release_set.filter(failed=False).latest()
        if (PTYPE_RUN in structure or release.build is None):
            if PTYPE_RUN in structure:
                err_msg = 'Cannot set scale for reserved types, procfile type is: run'
            else:
                err_msg = 'No build associated with this release'
            self.log(err_msg, logging.WARNING)
            raise DryccException(err_msg)
        app_settings = self.appsettings_set.latest()
        self._scale(user, structure, release, app_settings)

    def pipeline(self, release, ptypes=None, force_deploy=False):
        prefix = f"[pipeline] release {release.version_name}"
        try:
            if release.build is not None:
                if release.build.dryccfile:
                    for run in release.get_runners(ptypes):
                        self.log(f"{prefix} starts running pipeline.run {run['image']}")
                        job_name = self.run(
                            self.owner, run['image'], command=run['command'],
                            args=run['args'], timeout=run['timeout'], expires=run['timeout']
                        )
                        state, labels = 'initializing', {'job-name': job_name}
                        for count, state in enumerate(self.scheduler().pod.watch(
                                self.id, labels, settings.DRYCC_PILELINE_RUN_TIMEOUT)):
                            self.log(f"{prefix} waiting for pipeline.run: {state} * {count}")
                        if state != 'down':
                            raise DryccException(f'pipeline run state error: {state}')
                self.log(f"{prefix} starts running...")
                rollback_on_failure = self.appsettings_set.latest().autorollback
                if not rollback_on_failure:
                    self.log(f"{prefix} deploy do not rollback on failure")
                self.deploy(release, ptypes, force_deploy, rollback_on_failure)
            if release.state == "created":
                release.state = "succeed"
            ptypes = list(ptypes) if ptypes is not None else ptypes
            release.add_condition(state="succeed", action="pipeline", ptypes=ptypes)
        except Exception as e:
            release.failed, release.state = True, "crashed"
            ptypes = list(ptypes) if ptypes is not None else ptypes
            release.add_condition(
                state="crashed", action="pipeline", ptypes=ptypes, exception=str(e))
            self.log(f"{prefix} pipeline runtime error: {release.exception}", logging.ERROR)
        finally:
            DeployLock(self.pk).release(ptypes)
            release.save(update_fields=["state", "failed"])  # avoid overwriting other fields
        self.log(f"{prefix} run completed...")

    def deploy(self, release, ptypes=None, force_deploy=False, rollback_on_failure=True):
        """
        Deploy a new release to this application

        force_deploy can be used when a deployment is broken, such as for Rollback
        """
        if release.build is None:
            raise DryccException('No build associated with this release')
        # use create to make sure minimum resources are created
        self.create()
        # Previous release
        prev_release = release.previous()

        default_structure = self._default_structure(release)
        if (self.structure != default_structure) or (
            prev_release and prev_release.build and prev_release.build.type != release.build.type
        ):
            # structure {} or build type change, merge old structure if exists
            for ptype, scale in default_structure.items():
                default_structure[ptype] = self.structure.get(ptype, scale)
            self.structure = default_structure
            self.save()
        # deploy application to k8s. Also handles initial scaling
        app_settings = self.appsettings_set.latest()
        volumes = self.volume_set.all()
        deploys = {}
        for scale_type, replicas in self.structure.items():
            if ptypes is not None and scale_type not in ptypes:
                continue
            scale_type_volumes = [_ for _ in volumes if scale_type in _.path.keys()]
            deploys[scale_type] = self._gather_app_settings(
                release, app_settings, scale_type, replicas, volumes=scale_type_volumes)
        self._deploy(
            deploys, ptypes, prev_release, release, force_deploy, rollback_on_failure)
        # cleanup old release objects from kubernetes
        self.cleanup_old(ptypes)
        release.cleanup_old(ptypes)

    def mount(self, user, volume, structure=None):
        if self.release_set.filter(failed=False).latest().build is None:
            raise DryccException('No build associated with this release')
        release = self.release_set.filter(failed=False).latest()
        app_settings = self.appsettings_set.latest()
        self._mount(user, volume, release, app_settings, structure=structure)

    def cleanup_old(self, ptypes=None):
        names = []
        for scale_type in self.structure.keys():
            names.append(self._get_job_id(scale_type))
        labels = {'heritage': 'drycc'}
        if ptypes is not None:
            labels["type__in"] = ptypes
        deployments = self.scheduler().deployments.get(self.id, labels=labels).json()["items"]
        if deployments is not None:
            for deployment in deployments:
                name = deployment['metadata']['name']
                if name not in names:
                    self.scheduler().deployments.delete(self.id, name, True)
        self.log(f"cleanup old kubernetes deployments for {self.id}")

    def run(self, user, image=None, command=None, args=None, volumes=None,
            timeout=3600, expires=3600, **kwargs):
        def pod_name(size=5, chars=string.ascii_lowercase + string.digits):
            return ''.join(random.choice(chars) for _ in range(size))

        """Run a one-off command in an ephemeral app container."""
        release = self.release_set.filter(failed=False).latest()
        if release.build is None:
            raise DryccException('No build associated with this release to run this command')

        app_settings = self.appsettings_set.latest()
        volume_list = []
        if volumes:
            for volume in Volume.objects.filter(app=self, name__in=volumes.keys()):
                volume.path[PTYPE_RUN] = volumes.get(volume.name, None)
                volume_list.append(volume)
        else:
            for volume in Volume.objects.filter(app=self):
                if PTYPE_RUN in volume.path.keys():
                    volume_list.append(volume)
        data = self._gather_app_settings(
            release, app_settings, ptype=PTYPE_RUN,
            replicas=1, volumes=volume_list)
        data['restart_policy'] = 'Never'
        data['active_deadline_seconds'] = timeout
        data['ttl_seconds_after_finished'] = expires
        name = self._get_job_id(PTYPE_RUN) + '-' + pod_name()
        self.log("{} on {} runs '{}'".format(user.username, name, command))
        kwargs.update(data)
        try:
            # create application config and build the pod manifest
            self.set_application_config(release, PTYPE_RUN)
            self.scheduler().job.create(self.id, name, image, command, args, **kwargs)
        except Exception as e:
            err = '{} ({}): {}'.format(name, PTYPE_RUN, e)
            raise ServiceUnavailable(err) from e
        return name

    def describe_pod(self, pod_name):
        def get_command_and_args(pod, container_name):
            command, args = [], []
            for container in pod["spec"]["containers"]:
                if container["name"] == container_name:
                    args = container.get("args", [])
                    command = container.get("command", [])
                    break
            return command, args
        result = []
        try:
            pod = self.scheduler().pod.get(self.id, pod_name).json()
            for status in pod["status"]["containerStatuses"]:
                command, args = get_command_and_args(pod, status["name"])
                result.append({
                    "container": status["name"],
                    "image": status["image"],
                    "command": command,
                    "args": args,
                    "state": status["state"],
                    "lastState": status["lastState"],
                    "ready": status["ready"],
                    "restartCount": status["restartCount"],
                    "status": pod["status"].get("phase", ""),
                    "reason": pod["status"].get("reason", ""),
                    "message": pod["status"].get("message", "")
                })
        except KubeHTTPException as e:
            if e.response.status_code != 404:
                raise e
        return result

    def list_pods(self, *args, **kwargs):
        """Used to list basic information about pods running for a given application"""
        try:
            labels = self._scheduler_filter(**kwargs)
            # in case a singular pod is requested
            if 'name' in kwargs:
                pods = [self.scheduler().pod.get(self.id, kwargs['name']).json()]
            else:
                pods = self.scheduler().pod.get(self.id, labels=labels).json()['items']
                if not pods:
                    pods = []
            data = []
            for p in pods:
                labels = p['metadata']['labels']
                if 'startTime' in p['status']:
                    started = p['status']['startTime']
                else:
                    started = str(
                        datetime.now(timezone.utc).strftime(settings.DRYCC_DATETIME_FORMAT))
                item = {
                    'name': p['metadata']['name'], 'state': str(self.scheduler().pod.state(p)),
                    'release': labels['version'], 'type': labels['type'], 'started': started,
                    'ready': "%s/%s" % (
                        len([1 for s in p["status"]["containerStatuses"] if s['ready']]),
                        len(p["status"]["containerStatuses"]),
                    ),
                    'restarts': sum(
                        [s['restartCount'] for s in p["status"]["containerStatuses"]]),
                }
                data.append(item)
            # sorting so latest start date is first
            data.sort(key=lambda x: x['started'], reverse=True)
            return data
        except KubeHTTPException:
            pass
        except Exception as e:
            err = '(list pods): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

    def delete_pod(self, **kwargs):
        """Used to list basic information about pods running for a given application"""
        pod_name = kwargs.get('pod_name')
        try:
            # make sure the pod is manageed by drycc
            pod = self.scheduler().pod.get(self.id, pod_name).json()
            if pod['metadata']['labels'].get("heritage") == "drycc":
                self.scheduler().pod.delete(self.id, pod_name)
        except KubeHTTPException as e:
            # Sometimes k8s will manage to remove the pod from under us
            if e.response.status_code != 404:
                raise e

    def describe_deployment(self, deployment_name):
        result = []
        try:
            deployment = self.scheduler().deployment.get(self.id, deployment_name).json()
            for container in deployment["spec"]["template"]['spec']["containers"]:
                limits = container.get("resources", {}).get("limits", {})
                result.append({
                    "container": container["name"],
                    "image": container["image"],
                    "command": container.get("command", []),
                    "args": container.get("args", []),
                    "liveness_probe": container.get("livenessProbe", {}),
                    "readiness_probe": container.get("readinessProbe", {}),
                    "limits": limits,
                    "volume_mounts": container.get("volumeMounts", []),
                    "node_selector": deployment["spec"]["template"]['spec'].get("nodeSelector", {})  # noqa
                })
        except KubeHTTPException as e:
            if e.response.status_code != 404:
                raise e
        return result

    def list_deployments(self, *args, **kwargs):
        """Used to list basic information about deployments running for a given application"""
        try:
            labels = self._scheduler_filter(**kwargs)
            # in case a singular deployment is requested
            if 'name' in kwargs:
                deployments = [self.scheduler().deployment.get(self.id, kwargs['name']).json()]
            else:
                deployments = self.scheduler().deployment.get(self.id, labels=labels).json()['items']  # noqa
                if not deployments:
                    deployments = []
            data = []
            for p in deployments:
                labels = p['spec']['template']['metadata']['labels']
                if p['metadata']['creationTimestamp']:
                    started = p['metadata']['creationTimestamp']
                else:
                    started = str(
                        datetime.now(timezone.utc).strftime(settings.DRYCC_DATETIME_FORMAT))
                item = {
                    'name': labels['type'],
                    'release': labels['version'],
                    'ready': "%s/%s" % (
                        p["status"].get("readyReplicas", 0),
                        p["status"].get("replicas", 0),
                    ),
                    'up_to_date': p["status"].get("updatedReplicas", 0),
                    'available_replicas': p["status"].get("availableReplicas", 0),
                    'started': started
                }
                data.append(item)
            # sorting so latest start date is first
            data.sort(key=lambda x: x['started'], reverse=True)
            return data
        except KubeHTTPException:
            pass
        except Exception as e:
            err = '(list deployments): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

    def list_events(self, ref_kind, ref_name, *args, **kwargs):
        try:
            fields = {
                "regarding.kind": ref_kind,
                "regarding.name": ref_name
            }
            kwargs["fields"] = fields
            events = self.scheduler().events.get(self.id, **kwargs).json()['items']  # noqa
            data = []
            for e in events:
                item = {
                    'reason': e['reason'],
                    'message': e['note'],
                    'created': e['metadata']['creationTimestamp']
                }
                data.append(item)
            # sorting so latest start date is first
            data.sort(key=lambda x: x['created'], reverse=False)
            return data
        except KubeHTTPException:
            pass
        except Exception as e:
            err = '(list event): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

    def autoscale(self, proc_type, autoscale):
        """
        Set autoscale rules for the application
        """
        if proc_type == PTYPE_RUN:
            raise DryccException('Cannot set autoscale for reserved types, procfile type is: run')
        name = '{}-{}'.format(self.id, proc_type)
        # basically fake out a Deployment object (only thing we use) to assign to the HPA
        target = {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {'name': name}}

        try:
            # get the target for autoscaler, in this case Deployment
            self.scheduler().hpa.get(self.id, name)
            if autoscale is None:
                self.scheduler().hpa.delete(self.id, name)
            else:
                self.scheduler().hpa.update(
                    self.id, name, proc_type, target, **autoscale
                )
        except KubeHTTPException as e:
            if e.response.status_code == 404:
                self.scheduler().hpa.create(
                    self.id, name, proc_type, target, **autoscale
                )
            else:
                # let the user know about any other errors
                raise ServiceUnavailable(str(e)) from e

    def image_pull_secret(self, namespace, registry, image):
        """
        Take registry information and set as an imagePullSecret for an RC / Deployment
        http://kubernetes.io/docs/user-guide/images/#specifying-imagepullsecrets-on-a-pod
        """
        docker_config, name, create = self._get_private_registry_config(image, registry)
        if create is None:
            return
        elif create:
            data = {'.dockerconfigjson': docker_config}
            try:
                self.scheduler().secret.get(namespace, name)
            except KubeHTTPException:
                self.scheduler().secret.create(
                    namespace,
                    name,
                    data,
                    secret_type='kubernetes.io/dockerconfigjson'
                )
            else:
                self.scheduler().secret.update(
                    namespace,
                    name,
                    data,
                    secret_type='kubernetes.io/dockerconfigjson'
                )

        return name

    def state_to_k8s(self):
        release = self.release_set.filter(failed=False).latest()
        if release.build is None:
            self.log('the last release does not have a build, skipping deployment...')
            return
        ptypes = set()
        for ptype, scale in self.structure.items():
            response = self.scheduler().deployment.get(
                self.id, self._get_job_id(ptype),
                ignore_exception=True)
            if response.status_code == 404 and scale > 0:
                ptypes.add(ptype)
            elif response.status_code != 200:
                data = response.json()
                self.log('get deployment status_code {}, message: {}'.format(
                    response.status_code, data.get("message", "")), logging.ERROR)
        if len(ptypes) == 0:
            self.log('the cluster status is the latest, skipping deployment...')
            return
        self.deploy(release, ptypes, False, False)

    def set_application_config(self, release, ptype):
        """
        Creates the application config as a secret in Kubernetes and
        updates it if it already exists
        """
        # env vars are stored in secrets and mapped to env in k8s
        labels = {
            'version': release.version_name,
            'type': ptype,
            'class': 'env'
        }

        # secrets use dns labels for keys, map those properly here
        secrets_env = {}
        for key, value in self._build_env_vars(release, ptype).items():
            secrets_env[key.lower().replace('_', '-')] = str(value)

        # dictionary sorted by key
        secrets_env = OrderedDict(sorted(secrets_env.items(), key=lambda t: t[0]))

        secret_name = "{}-{}-{}-env".format(self.id, ptype, release.version_name)
        try:
            self.scheduler().secret.get(self.id, secret_name)
        except KubeHTTPException:
            self.scheduler().secret.create(self.id, secret_name, secrets_env, labels=labels)
        else:
            self.scheduler().secret.update(self.id, secret_name, secrets_env, labels=labels)

    def to_measurements(self, timestamp: float):
        measurements = []
        config = self.config_set.latest()
        for ptype, scale in self.structure.items():
            plan = config.limits.get(ptype)
            measurements.append({
                "app_id": str(self.uuid),
                "owner": self.owner_id,
                "name": plan,
                "type": "limits",
                "unit": "number",
                "usage": scale,
                "kwargs": {
                    "ptype": ptype,
                },
                "timestamp": int(timestamp),
            })
        return measurements

    def __str__(self):
        return self.id

    def _get_job_id(self, ptype):
        return f"{self.id}-{ptype}"

    def _clean_app_logs(self):
        """Delete application logs stored by the logger component"""
        try:
            url = 'http://{}:{}/logs/{}'.format(settings.LOGGER_HOST,
                                                settings.LOGGER_PORT, self.id)
            requests.delete(url)
        except Exception as e:
            # Ignore errors deleting application logs.  An error here should not interfere with
            # the overall success of deleting an application, but we should log it.
            err = 'Error deleting existing application logs: {}'.format(e)
            self.log(err, logging.WARNING)

    def _mount(self, user, volume, release, app_settings, structure=None):
        volumes = Volume.objects.filter(app=self)
        tasks = []
        for scale_type, replicas in structure.items() if structure else self.structure.items():
            if scale_type != PTYPE_RUN:
                replicas = self.structure.get(scale_type, 0)
                scale_type_volumes = [
                    volume for volume in volumes if scale_type in volume.path.keys()]
                data = self._gather_app_settings(
                    release, app_settings, scale_type, replicas, volumes=scale_type_volumes)
                deployment = self.scheduler().deployment.get(
                    self.id, self._get_job_id(scale_type)).json()
                spec_annotations = deployment['spec']['template']['metadata'].get(
                    'annotations', {})
                self.set_application_config(release, scale_type)
                # gather volume proc types to be deployed
                tasks.append(functools.partial(
                    self.scheduler().deployment.patch,
                    namespace=self.id,
                    name=self._get_job_id(scale_type),
                    image=release.get_deploy_image(scale_type),
                    command=release.get_deploy_command(scale_type),
                    args=release.get_deploy_args(scale_type),
                    spec_annotations=spec_annotations,
                    resource_version=deployment["metadata"]["resourceVersion"],
                    **data
                ))
        try:
            apply_tasks(tasks)
        except Exception as e:
            err = f'(changed volume mount for {volume}: {e}'
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e
        self.log(f'{user.username} changed volume mount for {volume}')

    def _deploy(self, deploys, ptypes, prev_release,
                release, force_deploy, rollback_on_failure):
        # Sort deploys so routable comes first
        deploys = OrderedDict(sorted(deploys.items(), key=lambda d: d[1].get('routable')))
        # Check if any proc type has a Deployment in progress
        self._check_deployment_in_progress(deploys, force_deploy)

        try:
            tasks = []
            for scale_type, kwargs in deploys.items():
                self.set_application_config(release, scale_type)
                tasks.append(functools.partial(
                    self.scheduler().deploy,
                    namespace=self.id,
                    name=self._get_job_id(scale_type),
                    image=release.get_deploy_image(scale_type),
                    command=release.get_deploy_command(scale_type),
                    args=release.get_deploy_args(scale_type),
                    **kwargs
                ))
            try:
                apply_tasks(tasks)
            except KubeException as e:
                # Don't rollback if the previous release doesn't have a build which means
                # this is the first build and all the previous releases are just config changes.
                if (rollback_on_failure and prev_release.build is not None):
                    err = 'There was a problem deploying {}. Rolling back to release {}.'.format(
                        release.version_name, prev_release.version_name)
                    # This goes in the log before the rollback starts
                    self.log(err, logging.ERROR)
                    # revert all process types to old release
                    self.deploy(prev_release, ptypes, True, False)
                    # let it bubble up
                    raise DryccException('{}\n{}'.format(err, str(e))) from e

                # otherwise just re-raise
                raise
        except Exception as e:
            # This gets shown to the end user
            err = '(app::deploy): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e
        for ptype in deploys.keys():
            if ptype == PTYPE_WEB:  # http
                target_port = release.get_port(ptype)
                self._create_default_ingress(target_port)
            service = self.service_set.filter(ptype=ptype).first()
            if not service:
                continue
            if prev_release and prev_release.build:
                continue
            if ptype == PTYPE_WEB:
                self._verify_http_health(service, **deploys[ptype])
            else:
                self._verify_tcp_health(service, **deploys[ptype])

    def _scale(self, user, structure, release, app_settings):  # noqa
        """Scale containers up or down to match requested structure."""
        # use create to make sure minimum resources are created
        self.create()
        # Validate structure
        try:
            for target, count in structure.copy().items():
                structure[target] = int(count)
            validate_app_structure(structure)
        except (TypeError, ValueError, ValidationError) as e:
            raise DryccException('Invalid scaling format: {}'.format(e))

        # test for available process types
        for ptype in structure:
            if ptype not in (PTYPE_WEB, PTYPE_RUN) and \
                    ptype not in release.ptypes:
                raise NotFound(
                    'Container type {} does not exist in application'.format(ptype))

        # merge current structure and the new items together
        old_structure = self.structure
        new_structure = old_structure.copy()
        new_structure.update(structure)
        if new_structure != self.structure:
            try:
                self._scale_pods(structure, release, app_settings)
            except ServiceUnavailable:
                # scaling failed, go back to old scaling numbers
                self._scale_pods(old_structure, release, app_settings)
                raise
            # save new structure to the database
            self.structure = new_structure
            self.save()
            msg = '{} scaled pods '.format(user.username) + ' '.join(
                "{}={}".format(k, v) for k, v in list(structure.items()))
            self.log(msg)
            return True
        return False

    def _scale_pods(self, scale_types, release, app_settings):
        volumes = Volume.objects.filter(app=self).exclude(path={})
        tasks = []
        for scale_type, replicas in scale_types.items():
            scale_type_volumes = [
                volume for volume in volumes if scale_type in volume.path.keys()]
            data = self._gather_app_settings(
                release, app_settings, scale_type, replicas, volumes=scale_type_volumes)
            # create the application config in k8s (secret in this case) for all deploy objects
            self.set_application_config(release, scale_type)
            # gather all proc types to be deployed
            tasks.append(
                functools.partial(
                    self.scheduler().scale,
                    namespace=self.id,
                    name=self._get_job_id(scale_type),
                    image=release.get_deploy_image(scale_type),
                    command=release.get_deploy_command(scale_type),
                    args=release.get_deploy_args(scale_type),
                    **data
                )
            )
        try:
            apply_tasks(tasks)
        except Exception as e:
            err = '(scale): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

    def _set_default_limit(self, config, ptype):
        if ptype not in config.limits:
            plan = LimitPlan.get_default()
            config.limits[ptype] = plan.id
            config.save(update_fields=['limits'])
        return config

    def _set_default_config(self):
        plan = LimitPlan.get_default()
        limits = {PTYPE_WEB: plan.id, PTYPE_RUN: plan.id}
        try:
            config = self.config_set.latest()
            limits[PTYPE_WEB] = config.limits.get(PTYPE_WEB, plan.id)
            limits[PTYPE_RUN] = config.limits.get(PTYPE_RUN, plan.id)
        except Config.DoesNotExist:
            config = Config.objects.create(owner=self.owner, app=self, limits=limits)
        for ptype in self.ptypes:
            limits[ptype] = config.limits.get(ptype, plan.id)
        if limits != config.limits:
            config.limits = limits
            config.save(update_fields=['limits'])
        return config

    def _create_default_ingress(self, target_port):
        # create default service
        try:
            service = self.service_set.filter(ptype=PTYPE_WEB).latest()
        except Service.DoesNotExist:
            service = Service(owner=self.owner, app=self, ptype=PTYPE_WEB)
            service.add_port(DEFAULT_HTTP_PORT, "TCP", target_port)
            service.save()
        else:
            if service.update_port(DEFAULT_HTTP_PORT, "TCP", target_port):
                service.save()
        # create default gateway
        try:
            gateway = self.gateway_set.filter(name=self.id).latest()
            if gateway.change_default_tls():
                gateway.save()
        except Gateway.DoesNotExist:
            gateway = Gateway(app=self, owner=self.owner, name=self.id)
            added, msg = gateway.add(DEFAULT_HTTP_PORT, "HTTP")
            if not added:
                raise DryccException(msg)
            gateway.save()
        # create default route
        try:
            route = self.route_set.filter(name=self.id).latest()
            if route.change_default_tls():
                route.save()
        except Route.DoesNotExist:
            route = Route(app=self, owner=self.owner, kind="HTTPRoute", name=self.id,
                          port=DEFAULT_HTTP_PORT, ptype=service.ptype)
            route.rules = route.default_rules
            attached, msg = route.attach(gateway.name, DEFAULT_HTTP_PORT)
            if not attached:
                raise DryccException(msg)
            route.save()

    def _verify_http_health(self, service, **kwargs):
        """
        Verify an application is healthy via the svc.
        This is only used in conjunction with the kubernetes health check system and should
        only run after kubernetes has reported all pods as healthy
        """

        app_type = kwargs.get('app_type')
        self.log(
            'Waiting for service to be ready to serve traffic to process type {}'.format(app_type),
            level=logging.DEBUG
        )
        url = 'http://{}:{}'.format(service.domain, service.ports[0]["port"])
        # if a httpGet probe is available then 200 is the only acceptable status code
        if ('livenessProbe' in kwargs.get('healthcheck', {}) and
                'httpGet' in kwargs['healthcheck']['livenessProbe']):
            allowed = [200]
            handler = kwargs['healthcheck']['livenessProbe']['httpGet']
            url = urljoin(url, handler.get('path', '/'))
            req_timeout = handler.get('timeoutSeconds', 1)
        else:
            allowed = set(range(200, 599))
            allowed.remove(404)
            req_timeout = 3
        # Give the svc max of 10 tries or max 30 seconds to become healthy
        # Uses time module to account for the timeout value of 3 seconds
        start = time.time()
        failed = False
        response = None
        for _ in range(10):
            try:
                # http://docs.python-requests.org/en/master/user/advanced/#timeouts
                response = get_session().get(url, timeout=req_timeout)
                failed = False
            except requests.exceptions.RequestException:
                # In case of a failure where response object is not available
                failed = True
                # We are fine with timeouts and request problems, lets keep trying
                time.sleep(1)  # just a bit of a buffer
                continue

            # 30 second timeout (timeout per request * 10)
            if (time.time() - start) > (req_timeout * 10):
                break

            # check response against the allowed pool
            if response.status_code in allowed:
                break

            # a small sleep since router usually resolve within 10 seconds
            time.sleep(1)

        # Endpoint did not report healthy in time
        if (response and response.status_code == 404) or failed:
            # bankers rounding
            delta = round(time.time() - start)
            self.log(
                'Router was not ready to serve traffic to process type {} in time, waited {} seconds'.format(app_type, delta),  # noqa
                level=logging.WARNING
            )
            return

        self.log(
            'Router is ready to serve traffic to process type {}'.format(app_type),
            level=logging.DEBUG
        )

    def _verify_tcp_health(self, service, **kwargs):
        for _ in range(10):
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(3)
                if sock.connect_ex((service.domain, service.ports[0]["port"])) == 0:
                    break
                else:
                    time.sleep(3)

    def _check_deployment_in_progress(self, deploys, force_deploy=False):
        if force_deploy:
            return
        for scale_type, kwargs in deploys.items():
            name = self._get_job_id(scale_type)
            # Is there an existing deployment in progress?
            in_progress, deploy_okay = self.scheduler().deployment.in_progress(
                self.id, name, kwargs.get("deploy_timeout"), kwargs.get("deploy_batches"),
                kwargs.get("replicas"), kwargs.get("tags")
            )
            # throw a 409 if things are in progress but we do not want to let through the deploy
            if in_progress and not deploy_okay:
                raise AlreadyExists('Deployment for {} is already in progress'.format(name))

    @staticmethod
    def _default_structure(release):
        """Scale to default structure based on release type"""
        structure = {PTYPE_WEB: 1}
        for ptype in release.ptypes:
            if ptype != PTYPE_WEB:
                structure[ptype] = 0
        return structure

    def _scheduler_filter(self, **kwargs):
        labels = {'app': self.id, 'heritage': 'drycc'}
        if 'type' in kwargs:
            labels.update({'type': kwargs['type']})
        if 'version' in kwargs:
            if isinstance(kwargs['version'], int):
                version = "v{}".format(kwargs['version'])
            else:
                version = kwargs['version']
            labels.update({'version': version})
        return labels

    def _build_env_vars(self, release, ptype):
        """
        Build a dict of env vars, setting default vars based on app type
        and then combining with the user set ones
        """
        if release.build is None:
            raise DryccException('No build associated with this release to run this command')

        # mix in default environment information drycc may require
        default_env = {
            'DRYCC_APP': self.id,
            'WORKFLOW_RELEASE': release.version_name,
            'WORKFLOW_RELEASE_SUMMARY': release.summary,
            'WORKFLOW_RELEASE_CREATED_AT': str(release.created.strftime(
                settings.DRYCC_DATETIME_FORMAT))
        }

        default_env['SOURCE_VERSION'] = release.build.sha
        # merge envs on top of default to make envs win
        default_env.update(release.config.values)
        default_env.update(release.config.typed_values.get(ptype, {}))
        # fetch application port and inject into ENV vars as needed
        port = release.get_port(ptype)
        if port:
            default_env['PORT'] = port
        return default_env

    def _get_private_registry_config(self, image, registry=None):
        name = settings.REGISTRY_SECRET_PREFIX
        if registry:
            # try to get the hostname information
            hostname = registry.get('hostname', None)
            if not hostname:
                hostname, _ = docker_auth.split_repo_name(image)

            if hostname == docker_auth.INDEX_NAME:
                hostname = docker_auth.INDEX_URL

            username = registry.get('username')
            password = registry.get('password')
        elif settings.REGISTRY_LOCATION == 'off-cluster':
            secret = self.scheduler().secret.get(
                settings.WORKFLOW_NAMESPACE, 'registry-secret').json()
            username = secret['data']['username']
            password = secret['data']['password']
            hostname = secret['data']['hostname']
            if hostname == '':
                hostname = docker_auth.INDEX_URL
            name = name + '-' + settings.REGISTRY_LOCATION
        else:
            return None, None, None

        # create / update private registry secret
        auth = bytes('{}:{}'.format(username, password), 'UTF-8')
        # value has to be a base64 encoded JSON
        docker_config = json.dumps({
            'auths': {
                hostname: {
                    'auth': base64.b64encode(auth).decode(encoding='UTF-8')
                }
            }
        })
        return docker_config, name, True

    def _get_volumes_and_mounts(self, ptype, volumes):
        k8s_volumes, k8s_volume_mounts = [], []
        if volumes:
            for volume in volumes:
                k8s_volume = {"name": volume.name}
                if volume.type == "csi":
                    k8s_volume.update({"persistentVolumeClaim": {"claimName": volume.name}})
                else:
                    k8s_volume.update(volume.parameters)
                k8s_volumes.append(k8s_volume)
                k8s_volume_mounts.append(
                    {"name": volume.name, "mountPath": volume.path.get(ptype)})
        return k8s_volumes, k8s_volume_mounts

    def _gather_app_settings(self, release, app_settings, ptype, replicas, volumes=None):
        """
        Gathers all required information needed in one easy place for passing into
        the Kubernetes client to deploy an application

        Any global setting that can also be set per app goes here
        """

        envs = self._build_env_vars(release, ptype)
        # Obtain a limit plan that must exist, if raise error here, it must be a bug
        config = self._set_default_limit(release.config, ptype)
        limit_plan = LimitPlan.objects.get(id=config.limits.get(ptype))

        # see if the app config has deploy batch preference, otherwise use global
        batches = int(config.values.get('DRYCC_DEPLOY_BATCHES', settings.DRYCC_DEPLOY_BATCHES))

        # see if the app config has deploy timeout preference, otherwise use global
        deploy_timeout = int(
            config.values.get('DRYCC_DEPLOY_TIMEOUT', settings.DRYCC_DEPLOY_TIMEOUT))

        # configures how many ReplicaSets to keep beside the latest version
        deployment_history = config.values.get(
            'KUBERNETES_DEPLOYMENTS_REVISION_HISTORY_LIMIT',
            settings.KUBERNETES_DEPLOYMENTS_REVISION_HISTORY_LIMIT)

        # get application level pod termination grace period
        pod_termination_grace_period_seconds = int(config.values.get(
            'KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS',
            settings.KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS))

        # set the image pull policy that is associated with the application container
        image_pull_policy = config.values.get('IMAGE_PULL_POLICY', settings.IMAGE_PULL_POLICY)

        # create image pull secret if needed
        image_pull_secret_name = self.image_pull_secret(
            self.id, config.registry, release.get_deploy_image(ptype))

        # only web is routable
        # https://www.drycc.cc/applications/managing-app-processes/#default-process-types
        routable = True if (
            ptype == PTYPE_WEB and app_settings.routable) else False

        healthcheck = config.healthcheck.get(ptype, {})
        volumes, volume_mounts = self._get_volumes_and_mounts(ptype, volumes)
        return {
            'tags': config.tags.get(ptype, {}),
            'envs': envs,
            'registry': config.registry,
            'replicas': replicas,
            'version': release.version_name,
            'app_type': ptype,
            'resources': {"limits": limit_plan.limits, "requests": limit_plan.requests},
            'build_type': release.build.type,
            'annotations': limit_plan.annotations,
            'healthcheck': healthcheck,
            'runtime_class_name': settings.DRYCC_APP_RUNTIME_CLASS,
            'dns_policy': settings.DRYCC_APP_DNS_POLICY,
            'lifecycle_post_start': config.lifecycle_post_start,
            'lifecycle_pre_stop': config.lifecycle_pre_stop,
            'routable': routable,
            'deploy_batches': batches,
            'restart_policy': "Always",
            'deploy_timeout': deploy_timeout,
            'deployment_revision_history_limit': deployment_history,
            'release_summary': release.summary,
            'pod_termination_grace_period_seconds': pod_termination_grace_period_seconds,
            'pod_termination_grace_period_each': config.termination_grace_period,
            'image_pull_secret_name': image_pull_secret_name,
            'image_pull_policy': image_pull_policy,
            'volumes': volumes,
            'volume_mounts': volume_mounts,
            'node_selector': limit_plan.node_selector,
            'pod_security_context': limit_plan.pod_security_context,
            'container_security_context': limit_plan.container_security_context,
        }
