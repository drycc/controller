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
        ptype = request["object"]["metadata"].get("labels", {}).get("type", "")
        if app and ptype:
            lock = app.lock()
            try:
                lock.acquire()
                status = request["object"]["status"]
                replicas = request["object"]["spec"].get("replicas", 0)
                if "active" in status:
                    replicas += 1
                elif "succeeded" in status or "failed" in status:
                    replicas -= 1
                replicas = 0 if replicas < 0 else replicas
                if app.structure.get(ptype, 0) != replicas:
                    models.app.App.objects.filter(id=app.id).update(
                        structure=Func(
                            F("structure"),
                            Value([ptype]),
                            Value(replicas, JSONField()),
                            function="jsonb_set",
                        )
                    )
            finally:
                lock.release()
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
        ptype = None
        for item in request["object"]["status"]["selector"].split(","):
            key, value = item.split("=")
            if key == "type":
                ptype = value
        if app and ptype:
            lock = app.lock()
            try:
                lock.acquire()
                replicas = request["object"]["spec"].get("replicas", 0)
                if app.structure.get(ptype, 0) != replicas:
                    models.app.App.objects.filter(id=app.id).update(
                        structure=Func(
                            F("structure"),
                            Value([ptype]),
                            Value(replicas, JSONField()),
                            function="jsonb_set",
                        )
                    )
            finally:
                lock.release()
        return True


class ServiceInstancesStatusHandler(BaseHandler):

    def detect(self, request: Request) -> bool:
        group = request.get("resource", {}).get("group", None)
        resource = "/".join([
            request.get("resource", {}).get("resource", None),
            request.get("subResource", ""),
        ])
        if (group, resource) == ("servicecatalog.k8s.io", "serviceinstances/status"):
            return True
        return False

    def handle(self, request: Request) -> bool:
        app_id = request["object"]["metadata"]["namespace"]
        name = request["object"]["metadata"]["name"]
        status = request["object"]["status"]["lastConditionState"]
        resource = models.resource.Resource.objects.filter(
            app__id=app_id, name=name).first()
        if resource and resource.status != status:
            resource.status = status
            resource.save(update_fields=["status"])
        return True


class ServicebindingsStatusHandler(BaseHandler):

    def detect(self, request: Request) -> bool:
        group = request.get("resource", {}).get("group", None)
        resource = "/".join([
            request.get("resource", {}).get("resource", None),
            request.get("subResource", ""),
        ])
        if (group, resource) == ("servicecatalog.k8s.io", "servicebindings/status"):
            return True
        return False

    def handle(self, request: Request) -> bool:
        app_id = request["object"]["metadata"]["namespace"]
        name = request["object"]["metadata"]["name"]
        binding = request["object"]["status"]["lastConditionState"]
        resource = models.resource.Resource.objects.filter(
            app__id=app_id, name=name).first()
        if resource and resource.binding != binding:
            resource.binding = binding
            resource.save(update_fields=["binding"])
        return True
