from django.db.models import F, Func, Value, JSONField
from rest_framework.request import Request

from api import models


class BaseHandler(object):

    def detect(self, request: Request) -> bool:
        raise NotImplementedError()

    def handle(self, request: Request) -> bool:
        raise NotImplementedError()


class JobsStatusHandler(BaseHandler):

    def detect(self, request: Request) -> bool:
        group = request.get("resource", {}).get("group", None)
        resource = "/".join([
            request.get("resource", {}).get("resource", None),
            request.get("subResource", ""),
        ])
        if (group, resource) == ("batch", "jobs/status"):
            return True
        return False

    def handle(self, request: Request) -> bool:
        app_id = request["object"]["metadata"]["namespace"]
        ptype = request["object"]["metadata"].get("labels", {}).get("type", "")
        if not ptype:
            return True
        status = request["object"]["status"]
        replicas = request["object"]["spec"].get("replicas", 0)
        if "active" in status:
            replicas += 1
        elif "succeeded" in status or "failed" in status:
            replicas -= 1
        replicas = 0 if replicas < 0 else replicas
        # jsonb_set on a single row is atomic at the PostgreSQL level; no lock
        # is needed because `replicas` is computed from the request payload
        # alone (not read-modify-write of app.structure). Filter touches 0 rows
        # if the app no longer exists, which is safe.
        models.app.App.objects.filter(id=app_id).update(
            structure=Func(
                F("structure"),
                Value([ptype]),
                Value(replicas, JSONField()),
                function="jsonb_set",
            )
        )
        return True


class DeploymentsScaleHandler(BaseHandler):

    def detect(self, request: Request) -> bool:
        group = request.get("resource", {}).get("group", None)
        resource = "/".join([
            request.get("resource", {}).get("resource", None),
            request.get("subResource", ""),
        ])
        if (group, resource) == ("apps", "deployments/scale"):
            return True
        return False

    def handle(self, request: Request) -> bool:
        app_id = request["object"]["metadata"]["namespace"]
        ptype = None
        for item in request["object"]["status"]["selector"].split(","):
            key, value = item.split("=")
            if key == "type":
                ptype = value
        if not ptype:
            return True
        replicas = request["object"]["spec"].get("replicas", 0)
        # jsonb_set is an atomic single-row UPDATE in PostgreSQL; no lock is
        # needed because `replicas` comes straight from the request payload.
        # Filter touches 0 rows if the app no longer exists, which is safe.
        models.app.App.objects.filter(id=app_id).update(
            structure=Func(
                F("structure"),
                Value([ptype]),
                Value(replicas, JSONField()),
                function="jsonb_set",
            )
        )
        return True
