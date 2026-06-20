import re

from django.db import models
from rest_framework.exceptions import ValidationError

from api.utils import validate_reserved_names, jsonpath
from api.exceptions import DryccException
from scheduler import KubeHTTPException, KubeException
from .base import UuidAuditedModel


def validate_addon_instance_name(value):
    """Check that the value follows the kubernetes name constraints."""
    if len(value) < 5:
        raise ValidationError("Addon instance name must be at least 5 characters long.")
    match = re.match(r'^[a-z]([a-z0-9-]*[a-z0-9])?$', value)
    if not match:
        raise ValidationError(
            "Addon instance name must start with a lowercase letter, cannot end with a"
            " hyphen and can only contain a-z (lowercase), 0-9 and hyphens.")
    validate_reserved_names(value)


class AddonInstance(UuidAuditedModel):
    app = models.ForeignKey("App", on_delete=models.CASCADE)
    name = models.CharField(max_length=63, validators=[validate_addon_instance_name])
    plan = models.CharField(max_length=128)
    kind = models.CharField(max_length=63)
    multiplier = models.PositiveIntegerField(default=1)
    parameters = models.JSONField(default=dict, blank=True)

    class Meta:
        unique_together = [("app", "name")]

    def __str__(self):
        return f"{self.kind}/{self.name}"

    def save(self, *args, **kwargs):
        old_instance = None
        if self.pk is not None:
            old_instance = AddonInstance.objects.filter(pk=self.pk).first()
        creating = old_instance is None
        if not creating and old_instance.kind.lower() != self.kind.lower():
            raise ValidationError(
                f"Addon kind cannot be changed from '{old_instance.kind}' to '{self.kind}'")

        addon_name = self.kind.lower()
        addonclass = self._get_addonclass(addon_name)
        plan = self._find_plan(addonclass, self.plan)
        if not plan:
            raise DryccException(f"Plan '{self.plan}' not found in {addon_name}")

        self.kind = addonclass["spec"]["targetResource"]["kind"]
        if creating:
            self._validate_user_params(self.parameters, plan)
        else:
            self._validate_user_params(
                self.parameters, plan, is_update=True,
                current_params=old_instance.parameters)
        self.multiplier = self._calc_multiplier(addonclass, plan, self.parameters)
        super().save(*args, **kwargs)
        self._apply_xr(plan)

    def delete(self, *args, **kwargs):
        try:
            self.scheduler.addonresources.delete(
                self.app.id, self.name, kind=self.kind, ignore_exception=True)
        except KubeException:
            pass
        return super().delete(*args, **kwargs)

    def get_conn(self):
        """Return decoded connection Secret data for this addon instance."""
        response = self.scheduler.addonresources.get(
            self.app.id, self.name, kind=self.kind, ignore_exception=True)
        if response.status_code == 404:
            raise DryccException(
                f"Addon '{self.name}' resource not found in namespace '{self.app.id}'")
        if self.scheduler.unhealthy(response.status_code):
            raise DryccException(
                f"Unable to retrieve addon resource '{self.name}': "
                f"{response.status_code}")
        secret_name = response.json().get('status', {}).get('connectionSecretName')
        if not secret_name:
            raise DryccException(
                f"Addon '{self.name}' connection secret is not ready")
        secret_response = self.scheduler.secret.get(self.app.id, secret_name)
        return secret_response.json().get('data', {})

    def _apply_xr(self, plan):
        response = self.scheduler.addonresources.get(
            self.app.id, self.name, kind=self.kind, ignore_exception=True)
        if response.status_code == 404:
            xr = {
                "apiVersion": "addons.drycc.cc/v1",
                "kind": self.kind,
                "metadata": {
                    "name": self.name,
                    "namespace": self.app.id,
                    "labels": {
                        "app.kubernetes.io/name": self.kind.lower(),
                        "app.drycc.cc/workspace": self.app.workspace.id,
                    },
                },
                "spec": {
                    "defaults": plan.get("defaults", {}),
                    "parameters": self.parameters,
                    "overrides": plan.get("overrides", {}),
                },
            }
            self.scheduler.addonresources.create(
                self.app.id, self.name, manifest=xr, kind=self.kind,
                ignore_exception=False)
        else:
            xr = response.json()
            xr["spec"]["parameters"].update(self.parameters)
            xr["spec"]["defaults"] = plan.get("defaults", {})
            xr["spec"]["overrides"] = plan.get("overrides", {})
            self.scheduler.addonresources.put(
                self.app.id, self.name, manifest=xr, kind=self.kind,
                ignore_exception=False)

    @staticmethod
    def _find_plan(addonclass, plan_name):
        plans = addonclass["spec"].get("plans", [])
        for p in plans:
            if p["name"] == plan_name:
                return p
        return None

    def _get_addonclass(self, addon_name):
        response = self.scheduler.addonclasses.get(addon_name, ignore_exception=True)
        if response.status_code == 404:
            raise DryccException(f"AddonClass '{addon_name}' not found")
        if self.scheduler.unhealthy(response.status_code):
            raise KubeHTTPException(response, f"fetching AddonClass '{addon_name}'")
        return response.json()

    @staticmethod
    def _calc_multiplier(addonclass, plan, params):
        field = addonclass.get("spec", {}).get("multiplierFrom")
        if field:
            return jsonpath(
                plan.get("overrides", {}), field,
                jsonpath(params, field,
                         jsonpath(plan.get("defaults", {}), field, 1)))
        return 1

    @staticmethod
    def _validate_user_params(params, plan, is_update=False, current_params=None):
        allow_create = set(plan.get("allowCreate", []))
        allow_update = set(plan.get("allowUpdate", []))

        def walk(data, prefix=''):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                if path in allow_update:
                    continue
                if path in allow_create:
                    if is_update and current_params is not None:
                        if jsonpath(current_params, path) != value:
                            raise ValidationError(
                                f"Field '{path}' is immutable for this plan")
                    continue
                if isinstance(value, dict):
                    walk(value, path)
                    continue
                raise ValidationError(f"Field '{path}' is not allowed for this plan")

        walk(params)
