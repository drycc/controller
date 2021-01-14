import backoff
import base64
import math
from collections import OrderedDict, defaultdict
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
from itertools import groupby
from urllib.parse import urljoin

from django.conf import settings
from django.db import models
from rest_framework.exceptions import ValidationError, NotFound
from jsonfield import JSONField

from api.models import get_session
from api.models import UuidAuditedModel, AlreadyExists, DryccException, ServiceUnavailable
from api.models.config import Config
from api.models.domain import Domain
from api.models.release import Release
from api.models.tls import TLS
from api.models.appsettings import AppSettings
from api.models.volume import Volume
from api.utils import generate_app_name, apply_tasks
from scheduler import KubeHTTPException, KubeException

logger = logging.getLogger(__name__)


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


class Pod(dict):
    pass


class App(UuidAuditedModel):
    """
    Application used to service requests on behalf of end-users
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    id = models.SlugField(max_length=63, unique=True, null=True,
                          validators=[validate_app_id,
                                      validate_reserved_names])
    structure = JSONField(default={}, blank=True, validators=[validate_app_structure])
    procfile_structure = JSONField(default={}, blank=True, validators=[validate_app_structure])

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

    def __str__(self):
        return self.id

    def _get_job_id(self, container_type):
        app = self.id
        return "{app}-{container_type}".format(**locals())

    @property
    def types(self):
        return list(self.procfile_structure.keys())

    def _get_command(self, container_type):
        """
        Return the kubernetes "container arguments" to be sent off to the scheduler.

        In reality this is the command that the user it attempting to run.
        """
        try:
            # FIXME: remove slugrunner's hardcoded entrypoint
            release = self.release_set.filter(failed=False).latest()
            if release.build.dockerfile or not release.build.sha:
                cmd = release.build.procfile[container_type]
                # if the entrypoint is `/bin/bash -c`, we want to supply the list
                # as a script. Otherwise, we want to send it as a list of arguments.
                if self._get_entrypoint(container_type) == ['/bin/bash', '-c']:
                    return [cmd]
                else:
                    return cmd.split()

            return ['start', container_type]
        # if the key is not present or if a parent attribute is None
        except (KeyError, TypeError, AttributeError):
            # handle special case for Dockerfile deployments
            return [] if container_type == 'cmd' else ['start', container_type]

    def _get_entrypoint(self, container_type):
        """
        Return the kubernetes "container command" to be sent off to the scheduler.

        In this case, it is the entrypoint for the docker image. Because of Heroku compatibility,
        Any containers that are not from a buildpack are run under /bin/bash.
        """
        # handle special case for Dockerfile deployments
        if container_type == 'cmd':
            return []

        # if this is a procfile-based app, switch the entrypoint to slugrunner's default
        # FIXME: remove slugrunner's hardcoded entrypoint
        release = self.release_set.filter(failed=False).latest()
        if release.build.procfile \
                and release.build.sha \
                and not release.build.dockerfile:
            entrypoint = ['/runner/init']
        else:
            entrypoint = ['/bin/bash', '-c']

        return entrypoint

    def _refresh_certificate(self, certs_auto_enabled, hosts):
        namespace = name = self.id
        try:
            data = self._scheduler.certificate.get(namespace, name).json()
        except KubeException:
            self.log("certificate {} does not exist".format(namespace), level=logging.INFO)
            data = None

        if certs_auto_enabled:
            if data:
                version = data["metadata"]["resourceVersion"]
                self._scheduler.certificate.put(
                    namespace, name, hosts, version)
            else:
                self._scheduler.certificate.create(
                    namespace, name, hosts)
        elif data:
            self._scheduler.certificate.delete(namespace, name)

    def _refresh_ingress(self, hosts, tls_map, ssl_redirect):
        ingress = namespace = self.id
        # Put Ingress
        kwargs = {
            "hosts": hosts,
            "tls": [{"secretName": k, "hosts": v} for k, v in tls_map.items()],
            "ssl_redirect": ssl_redirect
        }
        allowlist = self.appsettings_set.latest().allowlist
        if allowlist:
            kwargs.update({"allowlist": allowlist})
        try:
            # In order to create an ingress, we must first have a namespace.
            if ingress == "":
                raise ServiceUnavailable('Empty hostname')
            try:
                data = self._scheduler.ingress.get(namespace, ingress).json()
                version = data["metadata"]["resourceVersion"]
                self._scheduler.ingress.put(
                    ingress, settings.INGRESS_CLASS, namespace, version, **kwargs)
            except KubeException:
                self.log("creating Ingress {}".format(namespace), level=logging.INFO)
                self._scheduler.ingress.create(
                    ingress, settings.INGRESS_CLASS, namespace, **kwargs)
        except KubeException as e:
            raise ServiceUnavailable('Could not create Ingress in Kubernetes') from e

    def refresh(self):
        if not getattr(self, 'refresh_enabled', True):
            return
        app_settings = self.appsettings_set.latest()
        if not app_settings.routable:
            return
        tls = self.tls_set.latest()
        ssl_redirect = "true" if bool(tls.https_enforced) else "false"
        certs_auto_enabled = bool(tls.certs_auto_enabled)
        hosts, tls_map = [], defaultdict(list)
        for domain in Domain.objects.filter(app=self):
            host = str(domain.domain)
            hosts.append(host)
            if domain.certificate:
                secret_name = '%s-certificate' % domain.certificate.name
                tls_map[secret_name].append(host)
            if certs_auto_enabled and not domain.domain.startswith("*."):
                secret_name = '%s-certificate-auto' % self.id
                tls_map[secret_name].append(host)
        self._refresh_ingress(hosts, dict(tls_map), ssl_redirect)
        self._refresh_certificate(certs_auto_enabled, hosts)

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
            rel = self.release_set.latest()
        except Release.DoesNotExist:
            rel = Release.objects.create(
                version=1, owner=self.owner, app=self,
                config=cfg, build=None
            )

        # create required minimum resources in k8s for the application
        namespace = limits_name = quota_name = service = self.id
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
            try:
                self._scheduler.svc.get(namespace, service)
            except KubeException:
                self._scheduler.svc.create(namespace, service)
        except KubeException as e:
            # Blow it all away only if something horrible happens
            try:
                self._scheduler.ns.delete(namespace)
            except KubeException as e:
                # Just feed into the item below
                raise ServiceUnavailable('Could not delete the Namespace in Kubernetes') from e

            raise ServiceUnavailable('Kubernetes resources could not be created') from e
        try:
            setattr(self, 'refresh_enabled', False)  # do not refresh
            try:
                self.appsettings_set.latest()
            except AppSettings.DoesNotExist:
                AppSettings.objects.create(owner=self.owner, app=self)
            try:
                self.tls_set.latest()
            except TLS.DoesNotExist:
                TLS.objects.create(owner=self.owner, app=self)
            # Attach the platform specific application sub domain to the k8s service
            # Only attach it on first release in case a customer has remove the app domain
            domain = "%s.%s" % (self.id, settings.PLATFORM_DOMAIN)
            if rel.version == 1 and not Domain.objects.filter(domain=domain).exists():
                Domain.objects.create(owner=self.owner, app=self, domain=domain)
            # The default routable is true, so refresh ingress and tls
        finally:
            setattr(self, 'refresh_enabled', True)
        self.refresh()  # refresh

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
        Restart found pods by deleting them (RC / Deployment will recreate).
        Wait until they are all drained away and RC / Deployment has gotten to a good state
        """
        try:
            # Resolve single pod name if short form (cmd-1269180282-1nyfz) is passed
            if 'name' in kwargs and kwargs['name'].count('-') == 2:
                kwargs['name'] = '{}-{}'.format(kwargs['id'], kwargs['name'])

            # Iterate over RCs / RSs to get total desired count if not a single item
            desired = 1
            if 'name' not in kwargs:
                desired = 0
                labels = self._scheduler_filter(**kwargs)
                # fetch RS (which represent Deployments)
                controllers = self._scheduler.rs.get(kwargs['id'], labels=labels).json()['items']
                if not controllers:
                    controllers = []
                for controller in controllers:
                    desired += controller['spec']['replicas']
        except KubeException:
            # Nothing was found
            return []

        try:
            tasks = [
                functools.partial(
                    self._scheduler.pod.delete,
                    self.id,
                    pod['name']
                ) for pod in self.list_pods(**kwargs)
            ]

            apply_tasks(tasks)
        except Exception as e:
            err = "warning, some pods failed to stop:\n{}".format(str(e))
            self.log(err, logging.WARNING)

        # Wait for pods to start
        try:
            timeout = 300  # 5 minutes
            elapsed = 0
            while True:
                # timed out
                if elapsed >= timeout:
                    raise DryccException('timeout - 5 minutes have passed and pods are not up')

                # restarting a single pod behaves differently, fetch the *newest* pod
                # and hope it is the right one. Comes back sorted
                if 'name' in kwargs:
                    del kwargs['name']
                    pods = self.list_pods(**kwargs)
                    # Add in the latest name
                    if len(pods) == 0:
                        # if pod is not even scheduled wait for it and pass dummy kwargs
                        # to indicate restart of a single pod
                        kwargs['name'] = "dummy"
                        continue
                    kwargs['name'] = pods[0]['name']
                    pods = pods[0]

                actual = 0
                for pod in self.list_pods(**kwargs):
                    if pod['state'] == 'up':
                        actual += 1

                if desired == actual:
                    break

                elapsed += 5
                time.sleep(5)
        except Exception as e:
            err = "warning, some pods failed to start:\n{}".format(str(e))
            self.log(err, logging.WARNING)

        # Return the new pods
        pods = self.list_pods(**kwargs)
        return pods

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

    def scale(self, user, structure):  # noqa
        """Scale containers up or down to match requested structure."""
        # use create to make sure minimum resources are created
        self.create()

        if self.release_set.filter(failed=False).latest().build is None:
            raise DryccException('No build associated with this release')

        release = self.release_set.filter(failed=False).latest()

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
            if container_type == 'cmd':
                continue  # allow docker cmd types in case we don't have the image source

            if container_type not in available_process_types:
                raise NotFound(
                    'Container type {} does not exist in application'.format(container_type))

        # merge current structure and the new items together
        old_structure = self.structure
        new_structure = old_structure.copy()
        new_structure.update(structure)

        if new_structure != self.structure:
            # save new structure to the database
            self.structure = new_structure
            self.procfile_structure = release.build.procfile
            self.save()

            try:
                self._scale_pods(structure)
            except ServiceUnavailable:
                # scaling failed, go back to old scaling numbers
                self._scale_pods(old_structure)
                raise

            msg = '{} scaled pods '.format(user.username) + ' '.join(
                "{}={}".format(k, v) for k, v in list(structure.items()))
            self.log(msg)

            return True

        return False

    def stop(self, user, types):  # noqa
        """scale containers which types contained down """
        rs_zero = []
        for _ in types:
            if not self.structure.get(_, 0):
                rs_zero.append(_)
        if rs_zero:
            raise DryccException("process {} replicas is zero".format(",".join(rs_zero))) # noqa

        if self.release_set.filter(failed=False).latest().build is None:
            raise DryccException('No build associated with this release')

        release = self.release_set.filter(failed=False).latest()
        structure = {_: 0 for _ in types}

        # test for available process types
        available_process_types = release.build.procfile or {}
        for container_type in types:
            if container_type == 'cmd':
                continue  # allow docker cmd types in case we don't have the image source

            if container_type not in available_process_types:
                raise NotFound(
                    'Container type {} does not exist in application'.format(container_type))

        # merge current structure and the new items together
        old_structure = self.structure
        new_structure = old_structure.copy()
        new_structure.update(structure)

        if new_structure != self.structure:
            try:
                self._scale_pods(structure)
            except ServiceUnavailable:
                # scaling failed, go back to old scaling numbers
                self._scale_pods(old_structure)
                raise

            msg = '{} stopped pods '.format(user.username) + ' '.join(types)
            self.log(msg)

            return True

        return False

    def start(self, user, types):  # noqa
        """scale containers which types contained up."""
        # use create to make sure minimum resources are created
        self.create()
        if self.release_set.filter(failed=False).latest().build is None:
            raise DryccException('No build associated with this release')

        rs_zero = []
        for _ in types:
            if not self.structure.get(_, 0):
                rs_zero.append(_)
        if rs_zero:
            raise DryccException("process {} replicas is zero".format(",".join(rs_zero))) # noqa

        structure = {}
        for k, v in self.structure.items():
            if k in types:
                structure[k] = v
        try:
            self._scale_pods(structure)
        except ServiceUnavailable:
            # scaling failed, go back to old scaling numbers
            raise
        msg = '{} stopped pods '.format(user.username) + ' '.join(types)
        self.log(msg)
        return True

    def _scale_pods(self, scale_types):
        release = self.release_set.filter(failed=False).latest()
        app_settings = self.appsettings_set.latest()
        volumes = Volume.objects.filter(app=self, path__isnull=False)
        # use slugrunner image for app if buildpack app otherwise use normal image
        if release.build.type == 'buildpack':
            image = next(filter(lambda item: item['name'] == release.build.stack,
                                settings.SLUGRUNNER_IMAGES))['image']
        else:
            image = release.image

        tasks = []
        for scale_type, replicas in scale_types.items():
            scale_type_volumes = [_ for _ in volumes if scale_type in _.path.keys()]
            data = self._gather_app_settings(release, app_settings, scale_type, replicas, volumes=scale_type_volumes)  # noqa

            # gather all proc types to be deployed
            tasks.append(
                functools.partial(
                    self._scheduler.scale,
                    namespace=self.id,
                    name=self._get_job_id(scale_type),
                    image=image,
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

    def deploy(self, release, force_deploy=False, rollback_on_failure=True):  # noqa
        """
        Deploy a new release to this application

        force_deploy can be used when a deployment is broken, such as for Rollback
        """
        if release.build is None:
            raise DryccException('No build associated with this release')

        # use create to make sure minimum resources are created
        self.create()

        # set processes structure to default if app is new.
        if self.structure == {}:
            self.structure = self._default_structure(release)
            self.procfile_structure = self._default_structure(release)
            self.save()
        # reset canonical process types if build type has changed.
        else:
            # find the previous release's build type
            prev_release = release.previous()
            if prev_release and prev_release.build:
                if prev_release.build.type != release.build.type:
                    structure = self.structure.copy()
                    # zero out canonical pod counts
                    for proctype in ['cmd', 'web']:
                        if proctype in structure:
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
            deploys[scale_type] = self._gather_app_settings(release, app_settings, scale_type, replicas, volumes=scale_type_volumes)  # noqa

        # Sort deploys so routable comes first
        deploys = OrderedDict(sorted(deploys.items(), key=lambda d: d[1].get('routable')))

        # Check if any proc type has a Deployment in progress
        self._check_deployment_in_progress(deploys, force_deploy)

        # use slugrunner image for app if buildpack app otherwise use normal image
        if release.build.type == 'buildpack':
            image = next(filter(lambda item: item['name'] == release.build.stack,
                                settings.SLUGRUNNER_IMAGES))['image']
        else:
            image = release.image

        try:
            # create the application config in k8s (secret in this case) for all deploy objects
            self.set_application_config(release)
            # only buildpack apps need access to object storage
            if release.build.type == 'buildpack':
                self.create_object_store_secret()

            # gather all proc types to be deployed
            tasks = [
                functools.partial(
                    self._scheduler.deploy,
                    namespace=self.id,
                    name=self._get_job_id(scale_type),
                    image=image,
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
                if rollback_on_failure and release.previous().build is not None:
                    err = 'There was a problem deploying {}. Rolling back process types to release {}.'.format('v{}'.format(release.version), "v{}".format(release.previous().version))  # noqa
                    # This goes in the log before the rollback starts
                    self.log(err, logging.ERROR)
                    # revert all process types to old release
                    self.deploy(release.previous(), force_deploy=True, rollback_on_failure=False)
                    # let it bubble up
                    raise DryccException('{}\n{}'.format(err, str(e))) from e

                # otherwise just re-raise
                raise
        except Exception as e:
            # This gets shown to the end user
            err = '(app::deploy): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

        app_type = 'web' if 'web' in deploys else 'cmd' if 'cmd' in deploys else None
        # Make sure the application is routable and uses the correct port done after the fact to
        # let initial deploy settle before routing traffic to the application
        if deploys and app_type:
            routable = deploys[app_type].get('routable')
            port = deploys[app_type].get('envs', {}).get('PORT', None)
            self._update_application_service(self.id, app_type, port, routable)  # noqa
            # Wait until application is available in the router
            # Only run when there is no previous build / release
            old = release.previous()
            if old is None or old.build is None:
                self.verify_application_health(**deploys[app_type])
        # cleanup old release objects from kubernetes
        release.cleanup_old()

    def _set_default_config(self):
        default_cpu = "{}m".format(settings.KUBERNETES_LIMITS_DEFAULT_CPU)
        default_memory = "{}M".format(settings.KUBERNETES_LIMITS_DEFAULT_MEMORY)
        config = self.config_set.latest()
        new_cpu, new_memory = {}, {}
        for _type in self.types:
            new_cpu[_type] = config.cpu.get(_type, default_cpu)
            new_memory[_type] = config.memory.get(_type, default_memory)
        config.cpu = new_cpu
        config.memory = new_memory
        config.save()

    def _check_deployment_in_progress(self, deploys, force_deploy=False):
        if force_deploy:
            return
        for scale_type, kwargs in deploys.items():
            # Is there an existing deployment in progress?
            name = self._get_job_id(scale_type)
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
        # If web in procfile then honor it
        if release.build.procfile and 'web' in release.build.procfile:
            structure = {'web': 1}

        # if there is no SHA, assume a docker image is being promoted
        elif not release.build.sha:
            structure = {'cmd': 1}

        # if a dockerfile, assume docker workflow
        elif release.build.dockerfile:
            structure = {'cmd': 1}

        # if a procfile exists without a web entry and dockerfile, assume heroku workflow
        # and return empty structure as only web type needs to be created by default and
        # other types have to be manually scaled
        elif release.build.procfile and 'web' not in release.build.procfile:
            structure = {}

        # default to heroku workflow
        else:
            structure = {'web': 1}

        return structure

    def verify_application_health(self, **kwargs):
        """
        Verify an application is healthy via the router.
        This is only used in conjunction with the kubernetes health check system and should
        only run after kubernetes has reported all pods as healthy
        """
        # Bail out early if the application is not routable
        release = self.release_set.filter(failed=False).latest()
        app_settings = self.appsettings_set.latest()
        if not kwargs.get('routable', False) and app_settings.routable:
            return

        app_type = kwargs.get('app_type')
        self.log(
            'Waiting for router to be ready to serve traffic to process type {}'.format(app_type),
            level=logging.DEBUG
        )

        # Get the router host and append healthcheck path
        url = 'http://{}:{}'.format(settings.ROUTER_HOST, settings.ROUTER_PORT)

        # if a httpGet probe is available then 200 is the only acceptable status code
        if 'livenessProbe' in kwargs.get('healthcheck', {}) and 'httpGet' in kwargs.get('healthcheck').get('livenessProbe'):  # noqa
            allowed = [200]
            handler = kwargs['healthcheck']['livenessProbe']['httpGet']
            url = urljoin(url, handler.get('path', '/'))
            req_timeout = handler.get('timeoutSeconds', 1)
        else:
            allowed = set(range(200, 599))
            allowed.remove(404)
            req_timeout = 3

        # Give the router max of 10 tries or max 30 seconds to become healthy
        # Uses time module to account for the timeout value of 3 seconds
        start = time.time()
        failed = False
        headers = {
            # set the Host header for the application being checked - not used for actual routing
            'Host': '{}.{}.nip.io'.format(self.id, settings.ROUTER_HOST),
        }
        for _ in range(10):
            try:
                # http://docs.python-requests.org/en/master/user/advanced/#timeouts
                response = get_session().get(url, timeout=req_timeout, headers=headers)
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
        if ('response' in locals() and response.status_code == 404) or failed:
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

    @backoff.on_exception(backoff.expo, ServiceUnavailable, max_tries=3)
    def logs(self, log_lines=str(settings.LOG_LINES)):
        """Return aggregated log data for this application."""
        try:
            url = "http://{}:{}/logs/{}?log_lines={}".format(settings.LOGGER_HOST,
                                                             settings.LOGGER_PORT,
                                                             self.id, log_lines)
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
        # use slugrunner image for app if buildpack app otherwise use normal image
        if release.build.type == 'buildpack':
            image = next(filter(lambda item: item['name'] == release.build.stack,
                                settings.SLUGRUNNER_IMAGES))['image']
        else:
            image = release.image
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
        name = self._get_job_id(scale_type) + '-' + pod_name()
        self.log("{} on {} runs '{}'".format(user.username, name, command))

        try:
            exit_code, output = self._scheduler.run(
                self.id,
                name,
                image,
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
        autoscale = self.appsettings_set.latest().autoscale
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

                item = Pod()
                item['name'] = p['metadata']['name']
                item['state'] = state
                item['release'] = labels['version']
                item['type'] = labels['type']
                if 'startTime' in p['status']:
                    started = p['status']['startTime']
                else:
                    started = str(datetime.utcnow().strftime(settings.DRYCC_DATETIME_FORMAT))
                item['started'] = started
                replicas = str(autoscale[labels['type']]['min']) + '-' + str(autoscale[labels['type']]['max']) \
                    if autoscale.get(labels['type']) is not None else self.structure.get(labels['type'])  # noqa
                item['replicas'] = str(replicas)
                data.append(item)

            # sorting so latest start date is first
            data.sort(key=lambda x: x['started'], reverse=True)
            return data
        except KubeHTTPException as e:
            logger.debug(e)
        except Exception as e:
            err = '(list pods): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

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

        # Check if it is a slug builder image.
        if release.build.type == 'buildpack':
            # overwrite image so slugrunner image is used in the container
            default_env['SLUG_URL'] = release.image
            default_env['BUILDER_STORAGE'] = settings.APP_STORAGE
            default_env['DRYCC_MINIO_SERVICE_HOST'] = settings.MINIO_HOST
            default_env['DRYCC_MINIO_SERVICE_PORT'] = settings.MINIO_PORT

        if release.build.sha:
            default_env['SOURCE_VERSION'] = release.build.sha

        # fetch application port and inject into ENV vars as needed
        port = release.get_port()
        if port:
            default_env['PORT'] = port

        # merge envs on top of default to make envs win
        default_env.update(release.config.values)
        return default_env

    def routable(self, routable):
        """
        Turn on/off if an application is publically routable
        """
        if routable:
            self.refresh()
        else:
            try:
                namespace = ingress = self.id
                self._scheduler.ingress.delete(namespace, ingress)
            except KubeException as e:
                raise ServiceUnavailable(str(e)) from e

    def _update_application_service(self, namespace, app_type, port, routable=False):  # noqa
        """Update application service with all the various required information"""
        service = self._fetch_service_config(namespace)
        old_service = service.copy()  # in case anything fails for rollback

        try:
            # Set app type selector
            service['spec']['selector']['type'] = app_type

            # Find if target port exists already, update / create as required
            if routable:
                for pos, item in enumerate(service['spec']['ports']):
                    if item['port'] == 80 and port != item['targetPort']:
                        # port 80 is the only one we care about right now
                        service['spec']['ports'][pos]['targetPort'] = int(port)

            self._scheduler.svc.update(namespace, namespace, data=service)
        except Exception as e:
            # Fix service to old port and app type
            self._scheduler.svc.update(namespace, namespace, data=old_service)
            raise ServiceUnavailable(str(e)) from e

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

        # only web / cmd are routable
        # http://docs.drycc.cc/en/latest/using_drycc/process-types/#web-vs-cmd-process-types
        routable = True if process_type in ['web', 'cmd'] and app_settings.routable else False

        healthcheck = config.get_healthcheck().get(process_type, {})
        if not healthcheck and process_type in ['web', 'cmd']:
            healthcheck = config.get_healthcheck().get('web/cmd', {})
        volumes_info = [{
            "name": _.name,
            "claimName": _.name,
        } for _ in volumes] if volumes else []

        volume_mounts_info = [{
            "name": _.name,
            "mount_path": _.path.get(process_type),
        } for _ in volumes] if volumes else []

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
            'healthcheck': healthcheck,
            'lifecycle_post_start': config.lifecycle_post_start,
            'lifecycle_pre_stop': config.lifecycle_pre_stop,
            'routable': routable,
            'deploy_batches': batches,
            'deploy_timeout': deploy_timeout,
            'deployment_revision_history_limit': deployment_history,
            'release_summary': release.summary,
            'pod_termination_grace_period_seconds': pod_termination_grace_period_seconds,
            'pod_termination_grace_period_each': config.termination_grace_period,
            'image_pull_secret_name': image_pull_secret_name,
            'image_pull_policy': image_pull_policy,
            'volumes': volumes_info,
            'volume_mounts': volume_mounts_info,
        }

    def set_application_config(self, release):
        """
        Creates the application config as a secret in Kubernetes and
        updates it if it already exists
        """
        # env vars are stored in secrets and mapped to env in k8s
        version = 'v{}'.format(release.version)
        try:
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
            self._scheduler.secret.get(self.id, secret_name)
        except KubeHTTPException:
            self._scheduler.secret.create(self.id, secret_name, secrets_env, labels=labels)
        else:
            self._scheduler.secret.update(self.id, secret_name, secrets_env, labels=labels)

    def create_object_store_secret(self):
        try:
            self._scheduler.secret.get(self.id, 'objectstorage-keyfile')
        except KubeException:
            secret = self._scheduler.secret.get(
                settings.WORKFLOW_NAMESPACE, 'objectstorage-keyfile').json()
            self._scheduler.secret.create(self.id, 'objectstorage-keyfile', secret['data'])
