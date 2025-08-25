import logging
import functools
from django.db import models
from django.contrib.auth import get_user_model
from scheduler import KubeHTTPException
from api.exceptions import ServiceUnavailable
from api.utils import apply_tasks
from .app import App
from .base import UuidAuditedModel


User = get_user_model()
logger = logging.getLogger(__name__)


class Blocklist(UuidAuditedModel):
    """
    You can block apps or users.
    If a user is blocked, all apps owned by the user will be stopped.
    The apps managed by the user will not be affected.
    """
    type_choices = [(1, "app", ), (2, "user")]
    id = models.CharField(max_length=128, db_index=True)
    type = models.PositiveIntegerField(choices=type_choices)
    remark = models.TextField(blank=True, null=True, default="Blocked for unknown reason")

    @property
    def related_apps(self):
        if self.type == 2:
            user = User.objects.get(id=self.id)
            return App.objects.filter(owner=user)
        else:
            return App.objects.filter(id=self.id)

    @classmethod
    def get_type(cls, name: str):
        for _index, _name in cls.type_choices:
            if _name == name:
                return _index
        raise ValueError("This type was not found")

    @classmethod
    def get_blocklist(cls, app: App):
        return cls.objects.filter(
            models.Q(id=app.id, type=1) | models.Q(id=app.owner_id, type=2)
        ).first()

    class Meta:
        ordering = ['-created']
        unique_together = (("id", "type"),)

    def related_resource_deployments(self, app: App):
        "get resource deployments"
        try:
            deployments = self.scheduler.deployment.get(app.id, labels={}).json()['items']  # noqa
            if not deployments:
                deployments = []
            data = []
            for d in deployments:
                item = {
                    'name': d['metadata']['name'],
                    'replicas': d['spec'].get("replicas", 0),
                }
                data.append(item)
            data.sort(key=lambda x: x['name'])
            return data
        except KubeHTTPException:
            pass
        except Exception as e:
            err = f'(list resource deployments): {e}'
            logger.info(err)
            raise ServiceUnavailable(err) from e

    def related_resource_statefulsets(self, app: App):
        "get resource statefulsets"
        try:
            statefulsets = self.scheduler.statefulset.get(app.id, labels={}).json()['items']  # noqa
            if not statefulsets:
                statefulsets = []
            data = []
            for s in statefulsets:
                item = {
                    'name': s['metadata']['name'],
                    'replicas': s['spec'].get("replicas", 0),
                }
                data.append(item)
            data.sort(key=lambda x: x['name'])
            return data
        except KubeHTTPException:
            pass
        except Exception as e:
            err = f'(list resource statefulsets): {e}'
            logger.info(err)
            raise ServiceUnavailable(err) from e

    def related_resource_daemonsets(self, app: App):
        "get resource daemonsets"
        try:
            daemonsets = self.scheduler.daemonset.get(app.id, labels={}).json()['items']  # noqa
            if not daemonsets:
                daemonsets = []
            data = []
            for d in daemonsets:
                item = {
                    'name': d['metadata']['name'],
                    'affinity': d['spec']['template']['spec'].get('affinity', {}),
                }
                data.append(item)
            data.sort(key=lambda x: x['name'])
            return data
        except KubeHTTPException:
            pass
        except Exception as e:
            err = f'(list resource daemonsets): {e}'
            logger.info(err)
            raise ServiceUnavailable(err) from e

    def suspended_state(self, app: App):
        """
        Get deployments/statefulsets/daemonsets with labels app.kubernetes.io/managed-by=Helm
        Store in the suspended_state field of the app model
        Format:
        {"deployments": [{"name":"sample1", "replicas": 1}],
        "statefulsets": [{"name":"sample1", "replicas": 1}],
        "daemonsets": [{"name":"sample1", "affinity": {}}]}
        """
        suspended_state = {}
        suspended_state['deployments'] = self.related_resource_deployments(app)
        suspended_state['statefulsets'] = self.related_resource_statefulsets(app)
        suspended_state['daemonsets'] = self.related_resource_daemonsets(app)
        return suspended_state

    def scale_resource_deployments(self, app: App, deployment_name: str, replicas=0):
        """scale deployments"""
        try:
            deployment = self.scheduler.deployment.get(app.id, deployment_name).json()
            self.scheduler.scales.update(app.id, deployment_name, replicas, deployment)
        except KubeHTTPException:
            pass
        except Exception as e:
            err = f'(scale resource deployments): {e}'
            logger.info(err)
            raise ServiceUnavailable(err) from e

    def scale_resource_statefulsets(self, app: App, statefulset_name: str, replicas=0):
        """scale statefulsets"""
        try:
            self.scheduler.statefulset.get(app.id, statefulset_name).json()
            manifest = {
                'spec': {
                    'persistentVolumeClaimRetentionPolicy': {
                        'whenScaled': 'Retain'
                    },
                    'replicas': replicas
                }
            }
            self.scheduler.statefulset.patch(app.id, statefulset_name, manifest)
        except KubeHTTPException:
            pass
        except Exception as e:
            err = f'(scale resource statefulsets): {e}'
            logger.info(err)
            raise ServiceUnavailable(err) from e

    def scale_resource_daemonsets(self, app: App, daemonset_name: str, manifest: dict):
        """set affinity"""
        try:
            self.scheduler.daemonset.get(app.id, daemonset_name).json()
            self.scheduler.daemonset.patch(app.id, daemonset_name, manifest)
        except KubeHTTPException:
            pass
        except Exception as e:
            err = f'(scale resource daemonsets): {e}'
            logger.info(err)
            raise ServiceUnavailable(err) from e

    def scale_resources(self, app: App, suspended_state: dict, scale_type="block"):
        "scale resources tasks"
        tasks = []
        deployments = suspended_state.get('deployments', [])
        if not deployments:
            deployments = []
        for d in deployments:
            if scale_type == "unblock":
                replicas = d['replicas']
            else:
                replicas = 0
            tasks.append((
                functools.partial(
                    self.scale_resource_deployments,
                    app=app,
                    deployment_name=d['name'],
                    replicas=replicas
                ),
                lambda future, name=d["name"]: app.log(
                    f'{scale_type} scale deployment {name} callback: {future.result()}',
                )
            ))

        statefulsets = suspended_state.get('statefulsets', [])
        if not statefulsets:
            statefulsets = []
        for s in statefulsets:
            if scale_type == "unblock":
                replicas = s['replicas']
            else:
                replicas = 0
            tasks.append((
                functools.partial(
                    self.scale_resource_statefulsets,
                    app=app,
                    statefulset_name=s['name'],
                    replicas=replicas
                ),
                lambda future, name=s["name"]: app.log(
                    f'{scale_type} scale statefulset {name} callback: {future.result()}',
                )
            ))

        daemonsets = suspended_state.get('daemonsets', [])
        if not daemonsets:
            daemonsets = []
        for d in daemonsets:
            if scale_type == "unblock":
                manifest = {
                    "spec": {
                        "template": {
                            "spec": {
                                "affinity": d['affinity']
                            }
                        }
                    }
                }
            else:
                manifest = {
                    "spec": {
                        "template": {
                            "spec": {
                                "affinity": {
                                    "nodeAffinity": {
                                        "requiredDuringSchedulingIgnoredDuringExecution": {
                                            "nodeSelectorTerms": [{
                                                "matchExpressions": [{
                                                    "key": "kubernetes.io/hostname",
                                                    "operator": "In",
                                                    "values": [
                                                        "nohostname"
                                                    ]
                                                }]
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            tasks.append((
                functools.partial(
                    self.scale_resource_daemonsets,
                    app=app,
                    daemonset_name=d['name'],
                    manifest=manifest
                ),
                lambda future, name=d["name"]: app.log(
                    f'{scale_type} scale daemonset {name} callback: {future.result()}',
                )
            ))
        try:
            apply_tasks(tasks)
        except Exception as e:
            err = f'({scale_type} scale resources): {e}'
            logger.info(err)
            raise ServiceUnavailable(err) from e
