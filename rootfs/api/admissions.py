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
        app = models.app.App.objects.filter(id=app_id).first()
        container_type = request["object"]["metadata"].get("labels", {}).get("type", "")
        if app and container_type:
            status = request["object"]["status"]
            replicas = request["object"]["spec"].get("replicas", 0)
            if "active" in status:
                replicas += 1
            elif "succeeded" in status or "failed" in status:
                replicas -= 1
            replicas = 0 if replicas < 0 else replicas
            if app.structure.get(container_type, 0) != replicas:
                models.app.App.objects.filter(id=app.id).update(
                    structure=Func(
                        F("structure"),
                        Value([container_type]),
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
        app = models.app.App.objects.filter(id=app_id).first()
        container_type = None
        for item in request["object"]["status"]["selector"].split(","):
            key, value = item.split("=")
            if key == "type":
                container_type = value
        if app and container_type:
            replicas = request["object"]["spec"].get("replicas", 0)
            if app.structure.get(container_type, 0) != replicas:
                models.app.App.objects.filter(id=app.id).update(
                    structure=Func(
                        F("structure"),
                        Value([container_type]),
                        Value(replicas, JSONField()),
                        function="jsonb_set",
                    )
                )
        return True
