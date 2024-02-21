import backoff
import base64
import math
from collections import OrderedDict
from datetime import datetime
from docker import auth as docker_auth
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
from itertools import groupby
from urllib.parse import urljoin

from django.conf import settings
from django.db import models
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError, NotFound

from api.utils import get_session
from api.exceptions import AlreadyExists, DryccException, ServiceUnavailable
from api.utils import generate_app_name, apply_tasks, unit_to_bytes, unit_to_millicpu
from scheduler import KubeHTTPException, KubeException
from .gateway import Gateway, Route
from .config import Config
from .service import Service
from .release import Release
from .tls import TLS
from .appsettings import AppSettings
from .volume import Volume
from .base import UuidAuditedModel

User = get_user_model()
logger = logging.getLogger(__name__)


# http://kubernetes.io/v1.1/docs/design/identifiers.html
def validate_app_id(value):
    """
    Check that the value follows the kubernetes name constraints
    """
    match = re.match(r'[a-z]([a-z0-9-]*[a-z0-9])?(?<!-canary)$', value)
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
    procfile_structure = models.JSONField(
        default=dict, blank=True, validators=[validate_app_structure])

    class Meta:
        verbose_name = 'Application'
        permissions = (('use_app', 'Can use app'),)
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
                if self._scheduler.ns.get(self.id).status_code == 200:
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
    def types(self):
        return list(self.procfile_structure.keys())

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
        try:
            cfg = self.config_set.latest()
        except Config.DoesNotExist:
            cfg = Config.objects.create(owner=self.owner, app=self)

        # Only create if no release can be found
        try:
            self.release_set.latest()
        except Release.DoesNotExist:
            Release.objects.create(
                version=1, owner=self.owner, app=self,
                config=cfg, build=None
            )

        # create required minimum resources in k8s for the application
        namespace = limits_name = quota_name = self.id
        try:
            self.log('creating Namespace {} and services'.format(namespace), level=logging.DEBUG)
            # Create essential resources
            try:
                self._scheduler.ns.get(namespace)
            except KubeException:
                try:
                    self._scheduler.ns.create(namespace)
                except KubeException as e:
                    raise ServiceUnavailable('Could not create the Namespace in Kubernetes') from e

            if settings.KUBERNETES_NAMESPACE_DEFAULT_QUOTA_SPEC != '':
                quota_spec = json.loads(settings.KUBERNETES_NAMESPACE_DEFAULT_QUOTA_SPEC)
                self.log('creating Quota {} for namespace {}'.format(quota_name, namespace),
                         level=logging.DEBUG)
                try:
                    self._scheduler.quota.get(namespace, quota_name)
                except KubeException:
                    self._scheduler.quota.create(namespace, quota_name, spec=quota_spec)
            if settings.KUBERNETES_NAMESPACE_DEFAULT_LIMIT_RANGES_SPEC != '':
                limits_spec = json.loads(settings.KUBERNETES_NAMESPACE_DEFAULT_LIMIT_RANGES_SPEC)
                self.log('creating LimitRanges {} for namespace {}'.format(limits_name, namespace),
                         level=logging.DEBUG)
                try:
                    self._scheduler.limits.get(namespace, limits_name)
                except KubeException:
                    self._scheduler.limits.create(namespace, limits_name, spec=limits_spec)
        except KubeException as e:
            # Blow it all away only if something horrible happens
            try:
                self._scheduler.ns.delete(namespace)
            except KubeException as e:
                # Just feed into the item below
                raise ServiceUnavailable('Could not delete the Namespace in Kubernetes') from e

            raise ServiceUnavailable('Kubernetes resources could not be created') from e
        try:
            self.appsettings_set.latest()
        except AppSettings.DoesNotExist:
            AppSettings.objects.create(owner=self.owner, app=self)
        try:
            self.tls_set.latest()
        except TLS.DoesNotExist:
            TLS.objects.create(owner=self.owner, app=self)

    def delete(self, *args, **kwargs):
        """Delete this application including all containers"""
        self.log("deleting environment")
        try:
            # check if namespace exists
            self._scheduler.ns.get(self.id)

            try:
                self._scheduler.ns.delete(self.id)

                # wait 30 seconds for termination
                for _ in range(30):
                    try:
                        self._scheduler.ns.get(self.id)
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
        app_settings = self.appsettings_set.latest()
        if 'type' in kwargs and kwargs['type'] in self.structure:
            if self.structure[kwargs['type']] > 0:
                if kwargs['type'] in app_settings.canaries:
                    deployments.append(self._get_job_id(kwargs['type'], True))
                deployments.append(self._get_job_id(kwargs['type'], False))
        else:
            for scale_type, count in self.structure.items():
                if count > 0:
                    if scale_type in app_settings.canaries:
                        deployments.append(self._get_job_id(kwargs['type'], True))
                    deployments.append(self._get_job_id(scale_type, False))
        try:
            tasks = [
                functools.partial(
                    self._scheduler.deployment.restart,
                    self.id,
                    deployment
                ) for deployment in deployments
            ]
            apply_tasks(tasks)
        except Exception as e:
            err = "warning, some pods failed to restart:\n{}".format(str(e))
            self.log(err, logging.WARNING)

    def scale(self, user, structure):  # noqa
        if self.release_set.filter(failed=False).latest().build is None:
            raise DryccException('No build associated with this release')
        release = self.release_set.filter(failed=False).latest()
        app_settings = self.appsettings_set.latest()
        if release.canary:
            self._scale(
                user,
                structure,
                self.release_set.filter(failed=False, canary=False).latest(),
                app_settings
            )
        self._scale(user, structure, release, app_settings)

    def deploy(self, release, force_deploy=False, rollback_on_failure=True):  # noqa
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

        # set processes structure to default if app is new.
        if self.structure == {}:
            self.structure = self._default_structure(release)
            self.procfile_structure = self._default_structure(release)
            self.save()
        # reset canonical process types if build type has changed.
        else:
            # find the previous release's build type
            if prev_release and prev_release.build:
                if prev_release.build.type != release.build.type:
                    structure = self.structure.copy()
                    # zero out canonical pod counts
                    for proctype in structure.keys():
                        if proctype == "web":
                            structure[proctype] = 0
                    # update with the default process type.
                    structure.update(self._default_structure(release))
                    self.structure = structure
                    # if procfile structure exists then we use it
                    if release.build.procfile and \
                            release.build.sha and not \
                            release.build.dockerfile:
                        self.procfile_structure = release.build.procfile
                    self.save()

        # always set the procfile structure for any new release
        if release.build.procfile:
            self.procfile_structure = release.build.procfile
            self.save()

        # always set default config
        self._set_default_config()
        # deploy application to k8s. Also handles initial scaling
        app_settings = self.appsettings_set.latest()
        volumes = self.volume_set.all()
        deploys = {}
        for scale_type, replicas in self.structure.items():
            scale_type_volumes = [_ for _ in volumes if scale_type in _.path.keys()]
            if not release.canary or scale_type in app_settings.canaries:
                deploys[scale_type] = self._gather_app_settings(
                    release, app_settings, scale_type, replicas, volumes=scale_type_volumes)

        # Sort deploys so routable comes first
        deploys = OrderedDict(sorted(deploys.items(), key=lambda d: d[1].get('routable')))
        # Check if any proc type has a Deployment in progress
        self._check_deployment_in_progress(deploys, release, force_deploy)

        try:
            # create the application config in k8s (secret in this case) for all deploy objects
            self.set_application_config(release)

            # gather all proc types to be deployed
            tasks = [
                functools.partial(
                    self._scheduler.deploy,
                    namespace=self.id,
                    name=self._get_job_id(scale_type, release.canary),
                    image=release.image,
                    entrypoint=self._get_entrypoint(scale_type),
                    command=self._get_command(scale_type),
                    **kwargs
                ) for scale_type, kwargs in deploys.items()
            ]
            try:
                apply_tasks(tasks)
            except KubeException as e:
                # Don't rollback if the previous release doesn't have a build which means
                # this is the first build and all the previous releases are just config changes.
                if (prev_release.canary == release.canary and
                        rollback_on_failure and prev_release.build is not None):
                    err = 'There was a problem deploying {}. Rolling back to release {}.'.format(
                        'v{}'.format(release.version), "v{}".format(prev_release.version))
                    # This goes in the log before the rollback starts
                    self.log(err, logging.ERROR)
                    # revert all process types to old release
                    self.deploy(prev_release, force_deploy=True, rollback_on_failure=False)
                    # let it bubble up
                    raise DryccException('{}\n{}'.format(err, str(e))) from e

                # otherwise just re-raise
                raise
        except Exception as e:
            # This gets shown to the end user
            err = '(app::deploy): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e
        for procfile_type, value in deploys.items():
            if procfile_type == "web":  # http
                target_port = int(value.get('envs', {}).get('PORT', 5000))
                self._create_default_ingress(procfile_type, target_port)
            service = self.service_set.filter(procfile_type=procfile_type).first()
            if not service:
                continue
            if prev_release and prev_release.build:
                continue
            if procfile_type == "web":
                self._verify_http_health(service, **deploys[procfile_type])
            else:
                self._verify_tcp_health(service, **deploys[procfile_type])
        # cleanup old release objects from kubernetes
        self.cleanup_old()
        release.cleanup_old()

    def mount(self, user, volume):
        if self.release_set.filter(failed=False).latest().build is None:
            raise DryccException('No build associated with this release')
        release = self.release_set.filter(failed=False).latest()
        app_settings = self.appsettings_set.latest()
        if release.canary:
            self._mount(
                user,
                volume,
                self.release_set.filter(failed=False, canary=False).latest(),
                app_settings
            )
        self._mount(user, volume, release, app_settings)

    def cleanup_old(self):
        names, app_settings = [], self.appsettings_set.latest()
        for scale_type in self.structure.keys():
            if scale_type in app_settings.canaries:
                names.append(self._get_job_id(scale_type, True))
            names.append(self._get_job_id(scale_type, False))
        labels = {'heritage': 'drycc'}
        deployments = self._scheduler.deployments.get(self.id, labels=labels).json()["items"]
        if deployments is not None:
            for deployment in deployments:
                name = deployment['metadata']['name']
                if name not in names:
                    self._scheduler.deployments.delete(self.id, name, True)
        self.log(f"cleanup old kubernetes deployments for {self.id}")

    @backoff.on_exception(backoff.expo, ServiceUnavailable, max_tries=3)
    def logs(self, log_lines=str(settings.LOG_LINES)):
        """Return aggregated log data for this application."""
        url = "http://{}:{}/logs/{}?log_lines={}".format(
            settings.LOGGER_HOST, settings.LOGGER_PORT, self.id, log_lines)
        try:
            r = requests.get(url)
        # Handle HTTP request errors
        except requests.exceptions.RequestException as e:
            msg = "Error accessing drycc-logger using url '{}': {}".format(url, e)
            logger.error(msg)
            raise ServiceUnavailable(msg) from e

        # Handle logs empty or not found
        if r.status_code == 204 or r.status_code == 404:
            logger.info("GET {} returned a {} status code".format(url, r.status_code))
            raise NotFound('Could not locate logs')

        # Handle unanticipated status codes
        if r.status_code != 200:
            logger.error("Error accessing drycc-logger: GET {} returned a {} status code"
                         .format(url, r.status_code))
            raise ServiceUnavailable('Error accessing drycc-logger')

        # cast content to string since it comes as bytes via the requests object
        return str(r.content.decode('utf-8'))

    def run(self, user, command, volumes=None):
        def pod_name(size=5, chars=string.ascii_lowercase + string.digits):
            return ''.join(random.choice(chars) for _ in range(size))

        """Run a one-off command in an ephemeral app container."""
        release = self.release_set.filter(failed=False).latest()
        if release.build is None:
            raise DryccException('No build associated with this release to run this command')

        app_settings = self.appsettings_set.latest()
        volume_list = []
        if volumes:
            volume_objs = Volume.objects.filter(app=release.app, name__in=volumes.keys())
            for _ in volume_objs:
                _.path["run"] = volumes.get(_.name, None)  # noqa
                volume_list.append(_)
        data = self._gather_app_settings(release, app_settings, process_type='run', replicas=1, volumes=volume_list)  # noqa

        # create application config and build the pod manifest
        self.set_application_config(release)

        scale_type = 'run'
        name = self._get_job_id(scale_type, release.canary) + '-' + pod_name()
        self.log("{} on {} runs '{}'".format(user.username, name, command))

        try:
            exit_code, output = self._scheduler.run(
                self.id,
                name,
                release.image,
                self._get_entrypoint(scale_type),
                [command],
                **data
            )

            return exit_code, output
        except Exception as e:
            err = '{} (run): {}'.format(name, e)
            raise ServiceUnavailable(err) from e

    def list_pods(self, *args, **kwargs):
        """Used to list basic information about pods running for a given application"""
        try:
            labels = self._scheduler_filter(**kwargs)

            # in case a singular pod is requested
            if 'name' in kwargs:
                pods = [self._scheduler.pod.get(self.id, kwargs['name']).json()]
            else:
                pods = self._scheduler.pod.get(self.id, labels=labels).json()['items']
                if not pods:
                    pods = []

            data = []
            for p in pods:
                labels = p['metadata']['labels']
                # specifically ignore run pods
                if labels['type'] == 'run':
                    continue

                state = str(self._scheduler.pod.state(p))

                # follows kubelete convention - these are hidden unless show-all is set
                if state in ['down', 'crashed']:
                    continue

                # hide pod if it is passed the graceful termination period
                if self._scheduler.pod.deleted(p):
                    continue

                item = {}
                item['name'] = p['metadata']['name']
                item['state'] = state
                item['release'] = labels['version']
                item['type'] = labels['type']
                if 'startTime' in p['status']:
                    started = p['status']['startTime']
                else:
                    started = str(datetime.utcnow().strftime(settings.DRYCC_DATETIME_FORMAT))
                item['started'] = started

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

    def autoscale(self, proc_type, autoscale):
        """
        Set autoscale rules for the application
        """
        name = '{}-{}'.format(self.id, proc_type)
        # basically fake out a Deployment object (only thing we use) to assign to the HPA
        target = {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {'name': name}}

        try:
            # get the target for autoscaler, in this case Deployment
            self._scheduler.hpa.get(self.id, name)
            if autoscale is None:
                self._scheduler.hpa.delete(self.id, name)
            else:
                self._scheduler.hpa.update(
                    self.id, name, proc_type, target, **autoscale
                )
        except KubeHTTPException as e:
            if e.response.status_code == 404:
                self._scheduler.hpa.create(
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
                self._scheduler.secret.get(namespace, name)
            except KubeHTTPException:
                self._scheduler.secret.create(
                    namespace,
                    name,
                    data,
                    secret_type='kubernetes.io/dockerconfigjson'
                )
            else:
                self._scheduler.secret.update(
                    namespace,
                    name,
                    data,
                    secret_type='kubernetes.io/dockerconfigjson'
                )

        return name

    def set_application_config(self, release):
        """
        Creates the application config as a secret in Kubernetes and
        updates it if it already exists
        """
        # env vars are stored in secrets and mapped to env in k8s
        version = 'v{}'.format(release.version)
        labels = {
            'version': version,
            'type': 'env'
        }

        # secrets use dns labels for keys, map those properly here
        secrets_env = {}
        for key, value in self._build_env_vars(release).items():
            secrets_env[key.lower().replace('_', '-')] = str(value)

        # dictionary sorted by key
        secrets_env = OrderedDict(sorted(secrets_env.items(), key=lambda t: t[0]))

        secret_name = "{}-{}-env".format(self.id, version)
        try:
            self._scheduler.secret.get(self.id, secret_name)
        except KubeHTTPException:
            self._scheduler.secret.create(self.id, secret_name, secrets_env, labels=labels)
        else:
            self._scheduler.secret.update(self.id, secret_name, secrets_env, labels=labels)

    def to_measurements(self, timestamp: float):
        measurements = []
        config = self.config_set.latest()
        for container_type, scale in self.structure.items():
            measurements.append({
                "app_id": str(self.uuid),
                "owner": self.owner_id,
                "name": container_type,
                "type": "cpu",
                "unit": "milli",
                "usage": unit_to_millicpu(config.cpu.get(container_type)) * scale,
                "timestamp": int(timestamp)
            })
            measurements.append({
                "app_id": str(self.uuid),
                "owner": self.owner_id,
                "name": container_type,
                "type": "memory",
                "unit": "bytes",
                "usage": unit_to_bytes(config.memory.get(container_type)) * scale,
                "timestamp": int(timestamp)
            })
        return measurements

    def __str__(self):
        return self.id

    def _get_job_id(self, container_type, canary):
        job_id = f"{self.id}-{container_type}"
        if canary:
            job_id = f"{job_id}-canary"
        return job_id

    def _get_command(self, container_type):
        """
        Return the kubernetes "container arguments" to be sent off to the scheduler.
        """
        release = self.release_set.filter(failed=False).latest()
        if release is not None and release.build is not None:
            # dockerfile or container image
            if release.build.dockerfile or not release.build.sha:
                # has profile
                if release.build.procfile and container_type in release.build.procfile:
                    command = release.build.procfile[container_type]
                    return command.split()
        return []

    def _get_stack(self, release):
        stack = release.config.values.get("DRYCC_STACK", None)
        if stack is None:
            if release.build.procfile \
                    and release.build.sha \
                    and not release.build.dockerfile:
                stack = "buildpack"
            else:
                stack = "container"
        return stack

    def _get_entrypoint(self, container_type):
        """
        Return the kubernetes "container command" to be sent off to the scheduler.
        """
        entrypoint = []
        release = self.release_set.filter(failed=False).latest()
        if self._get_stack(release) == "buildpack":
            if container_type in release.build.procfile:
                entrypoint = [container_type]
            else:
                entrypoint = ['launcher']
        return entrypoint

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

    def _mount(self, user, volume, release, app_settings):
        volumes = list(Volume.objects.filter(app=self).exclude(name=volume.name))
        volumes.append(volume)
        tasks = []
        for scale_type, replicas in self.structure.items():
            if not release.canary or scale_type in app_settings.canaries:
                replicas = self.structure.get(scale_type, 0)
                scale_type_volumes = [_ for _ in volumes if scale_type in _.path.keys()]
                data = self._gather_app_settings(
                    release, app_settings, scale_type, replicas, volumes=scale_type_volumes)
                deployment = self._scheduler.deployment.get(
                    self.id, self._get_job_id(scale_type, release.canary)).json()
                spec_annotations = deployment['spec']['template']['metadata'].get(
                    'annotations', {})
                # gather volume proc types to be deployed
                tasks.append(
                    functools.partial(
                        self._scheduler.deployment.patch,
                        namespace=self.id,
                        name=self._get_job_id(scale_type, release.canary),
                        image=release.image,
                        entrypoint=self._get_entrypoint(scale_type),
                        command=self._get_command(scale_type),
                        spec_annotations=spec_annotations,
                        resource_version=deployment["metadata"]["resourceVersion"],
                        **data
                    )
                )
        try:
            # create the application config in k8s (secret in this case) for all deploy objects
            self.set_application_config(release)
            apply_tasks(tasks)
        except Exception as e:
            err = f'(changed volume mount for {volume}: {e}'
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

        msg = f'{user.username} changed volume mount for {volume}'
        self.log(msg)

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
        available_process_types = release.build.procfile or {}
        for container_type in structure:
            if self._get_stack(release) == "container":
                continue  # allow container types in case we don't have the image source
            if container_type not in available_process_types:
                raise NotFound(
                    'Container type {} does not exist in application'.format(container_type))

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
            self.procfile_structure = release.build.procfile
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
            scale_type_volumes = [_ for _ in volumes if scale_type in _.path.keys()]
            data = self._gather_app_settings(release, app_settings, scale_type, replicas, volumes=scale_type_volumes)  # noqa
            # gather all proc types to be deployed
            tasks.append(
                functools.partial(
                    self._scheduler.scale,
                    namespace=self.id,
                    name=self._get_job_id(scale_type, release.canary),
                    image=release.image,
                    entrypoint=self._get_entrypoint(scale_type),
                    command=self._get_command(scale_type),
                    **data
                )
            )
        try:
            # create the application config in k8s (secret in this case) for all deploy objects
            self.set_application_config(release)
            apply_tasks(tasks)
        except Exception as e:
            err = '(scale): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

    def _set_default_config(self):
        default_cpu = "{}m".format(settings.KUBERNETES_LIMITS_MIN_CPU)
        default_memory = "{}M".format(settings.KUBERNETES_LIMITS_MIN_MEMORY)
        config = self.config_set.latest()
        new_cpu, new_memory = {}, {}
        for _type in self.types:
            new_cpu[_type] = config.cpu.get(_type, default_cpu)
            new_memory[_type] = config.memory.get(_type, default_memory)
        config.cpu = new_cpu
        config.memory = new_memory
        config.save()

    def _create_default_ingress(self, procfile_type, target_port):
        port = 80
        # create default service
        try:
            service = self.service_set.filter(procfile_type=procfile_type).latest()
        except Service.DoesNotExist:
            service = Service(owner=self.owner, app=self, procfile_type=procfile_type)
            service.add_port(port, "TCP", target_port)
            service.save()
        # create default gateway
        try:
            gateway = self.gateway_set.filter(name=self.id).latest()
        except Gateway.DoesNotExist:
            gateway = Gateway(app=self, owner=self.owner, name=self.id)
            added, msg = gateway.add(port, "HTTP")
            if not added:
                raise DryccException(msg)
            gateway.save()
        # create default route
        try:
            self.route_set.filter(name=self.id).latest()
        except Route.DoesNotExist:
            route = Route(app=self, owner=self.owner, kind="HTTPRoute", name=self.id,
                          port=port, procfile_type=service.procfile_type)
            route.rules = route.default_rules
            attached, msg = route.attach(gateway.name, port)
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

    def _check_deployment_in_progress(self, deploys, release, force_deploy=False):
        if force_deploy:
            return
        for scale_type, kwargs in deploys.items():
            name = self._get_job_id(scale_type, release.canary)
            # Is there an existing deployment in progress?
            in_progress, deploy_okay = self._scheduler.deployment.in_progress(
                self.id, name, kwargs.get("deploy_timeout"), kwargs.get("deploy_batches"),
                kwargs.get("replicas"), kwargs.get("tags")
            )
            # throw a 409 if things are in progress but we do not want to let through the deploy
            if in_progress and not deploy_okay:
                raise AlreadyExists('Deployment for {} is already in progress'.format(name))

    @staticmethod
    def _default_structure(release):
        """Scale to default structure based on release type"""
        if release.build.sha and not release.build.dockerfile and \
                (release.build.procfile and 'web' not in release.build.procfile):
            structure = {}
        # default to heroku workflow
        else:
            structure = {'web': 1}
        return structure

    def _scheduler_filter(self, **kwargs):
        labels = {'app': self.id, 'heritage': 'drycc'}

        # always supply a version, either latest or a specific one
        if 'release' not in kwargs or kwargs['release'] is None:
            release = self.release_set.filter(failed=False).latest()
        else:
            release = self.release_set.get(version=kwargs['release'])

        version = "v{}".format(release.version)
        labels.update({'version': version})

        if 'type' in kwargs:
            labels.update({'type': kwargs['type']})

        return labels

    def _build_env_vars(self, release):
        """
        Build a dict of env vars, setting default vars based on app type
        and then combining with the user set ones
        """
        if release.build is None:
            raise DryccException('No build associated with this release to run this command')

        # mix in default environment information drycc may require
        default_env = {
            'DRYCC_APP': self.id,
            'WORKFLOW_RELEASE': 'v{}'.format(release.version),
            'WORKFLOW_RELEASE_SUMMARY': release.summary,
            'WORKFLOW_RELEASE_CREATED_AT': str(release.created.strftime(
                settings.DRYCC_DATETIME_FORMAT))
        }

        default_env['SOURCE_VERSION'] = release.build.sha

        # fetch application port and inject into ENV vars as needed
        port = release.get_port()
        if port:
            default_env['PORT'] = port

        # merge envs on top of default to make envs win
        default_env.update(release.config.values)
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
            secret = self._scheduler.secret.get(
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

    @staticmethod
    def _get_request_cpu(size):
        cpu_request_ratio = settings.KUBERNETES_REQUEST_CPU_RATIO
        if size.isdigit():
            unit = 'm'
            num = (int(size) * 1000) / cpu_request_ratio
        else:
            num, unit = (
                ''.join(item[1]) for item in groupby(
                    size, key=lambda x: x.isdigit()
                )
            )
            if unit not in ["m", "M"]:
                raise DryccException("Units are represented in the number or milli of CPUs")
            else:
                num = int(num) / cpu_request_ratio
        return "{num}{unit}".format(num=math.ceil(num), unit=unit)

    @staticmethod
    def _get_request_memory(size):
        memory_request_ratio = settings.KUBERNETES_REQUEST_MEMORY_RATIO
        num, unit = (
            ''.join(item[1]) for item in groupby(
                size, key=lambda x: x.isdigit()
            )
        )
        if unit in ['G', 'g']:
            unit = 'M'
            num = (int(num) * 1024) / memory_request_ratio
        elif unit in ['M', 'm']:
            num = int(num) / memory_request_ratio
        else:
            raise DryccException('Units are represented in Megabytes(M), or Gigabytes (G)')
        return "{num}{unit}".format(num=math.ceil(num), unit=unit)

    def _get_volumes_and_mounts(self, process_type, volumes):
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
                    {"name": volume.name, "mountPath": volume.path.get(process_type)})
        k8s_volumes.extend(json.loads(settings.KUBERNETES_POD_DEFAULT_VOLUMES))
        k8s_volume_mounts.extend(json.loads(settings.KUBERNETES_POD_DEFAULT_VOLUME_MOUNTS))
        return k8s_volumes, k8s_volume_mounts

    def _gather_app_settings(self, release, app_settings, process_type, replicas, volumes=None):
        """
        Gathers all required information needed in one easy place for passing into
        the Kubernetes client to deploy an application

        Any global setting that can also be set per app goes here
        """
        envs = self._build_env_vars(release)
        config = release.config
        cpu, memory = {}, {}
        for key, value in config.cpu.items():
            cpu[key] = "%s/%s" % (self._get_request_cpu(value), value)
        for key, value in config.memory.items():
            memory[key] = "%s/%s" % (self._get_request_memory(value), value)
        # see if the app config has deploy batch preference, otherwise use global
        batches = int(config.values.get('DRYCC_DEPLOY_BATCHES', settings.DRYCC_DEPLOY_BATCHES))  # noqa

        # see if the app config has deploy timeout preference, otherwise use global
        deploy_timeout = int(config.values.get('DRYCC_DEPLOY_TIMEOUT', settings.DRYCC_DEPLOY_TIMEOUT))  # noqa

        # configures how many ReplicaSets to keep beside the latest version
        deployment_history = config.values.get('KUBERNETES_DEPLOYMENTS_REVISION_HISTORY_LIMIT',
                                               settings.KUBERNETES_DEPLOYMENTS_REVISION_HISTORY_LIMIT)  # noqa

        # get application level pod termination grace period
        pod_termination_grace_period_seconds = int(config.values.get(
            'KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS', settings.KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS))  # noqa

        # set the image pull policy that is associated with the application container
        image_pull_policy = config.values.get('IMAGE_PULL_POLICY', settings.IMAGE_PULL_POLICY)

        # create image pull secret if needed
        image_pull_secret_name = self.image_pull_secret(self.id, config.registry, release.image)

        # only web is routable
        # https://www.drycc.cc/applications/managing-app-processes/#default-process-types
        routable = True if process_type == 'web' and app_settings.routable else False

        healthcheck = config.get_healthcheck().get(process_type, {})
        if not healthcheck and process_type == 'web':
            healthcheck = config.get_healthcheck().get('web', {})
        volumes, volume_mounts = self._get_volumes_and_mounts(process_type, volumes)
        return {
            'memory': memory,
            'cpu': cpu,
            'tags': config.tags,
            'envs': envs,
            'registry': config.registry,
            'replicas': replicas,
            'version': 'v{}'.format(release.version),
            'app_type': process_type,
            'resources': json.loads(settings.KUBERNETES_POD_DEFAULT_RESOURCES),
            'build_type': release.build.type,
            'annotations': json.loads(settings.KUBERNETES_POD_DEFAULT_ANNOTATIONS),
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
            'security_context': json.loads(settings.KUBERNETES_POD_DEFAULT_SECURITY_CONTEXT),
        }
