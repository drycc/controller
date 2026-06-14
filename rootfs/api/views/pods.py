"""
Pod and event views.
"""
from rest_framework import status
from rest_framework.response import Response

from api import models, serializers
from api.exceptions import DryccException
from api.views.app import AppFilterViewSet
from api.tasks import scale_app, restart_app, delete_pod


class PodViewSet(AppFilterViewSet):
    model = models.app.App
    serializer_class = serializers.PodSerializer

    def list(self, *args, **kwargs):
        pods = self.get_app().list_pods(*args, **kwargs)
        data = self.get_serializer(pods, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def describe(self, *args, **kwargs):
        pod_name = kwargs["name"]
        data = self.get_app().describe_pod(pod_name)
        if len(data) == 0:
            raise DryccException("this process not found")
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def destroy(self, request, **kwargs):
        pod_names = request.data.get("pod_ids")
        pod_names = pod_names.split(",")
        for pod_name in set(pod_names):
            delete_pod.delay(self.get_app(), **{"pod_name": pod_name})
        return Response(status=status.HTTP_200_OK)


class PtypeViewSet(AppFilterViewSet):
    model = models.app.App
    serializer_class = serializers.PtypeSerializer

    def list(self, *args, **kwargs):
        deploys = self.get_app().list_deployments(*args, **kwargs)
        data = self.get_serializer(deploys, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def describe(self, *args, **kwargs):
        deployment_name = kwargs["name"]
        data = self.get_app().describe_deployment(deployment_name)
        if len(data) == 0:
            raise DryccException("this procfile type not found")
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def restart(self, request, *args, **kwargs):
        app = self.get_app()
        ptypes = set(
            [ptype for ptype in request.data.get("ptypes", "").split(",") if ptype])
        ptypes = app.check_ptypes(ptypes)
        for ptype in set(ptypes):
            restart_app.delay(app, **{"type": ptype})
        return Response(status=status.HTTP_204_NO_CONTENT)

    def clean(self, request, *args, **kwargs):
        app = self.get_app()
        ptypes = set(
            [ptype for ptype in request.data.get("ptypes", "").split(",") if ptype])
        if not ptypes:
            raise DryccException("ptypes is a required field")
        latest_ptypes = [k for k, v in app.structure.items() if v != 0]
        not_allow = [ptype for ptype in ptypes if ptype in latest_ptypes]
        if not_allow:
            raise DryccException(f'ptype {",".join(not_allow)} should not garbage.')
        app.clean(ptypes=ptypes)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def scale(self, request, **kwargs):
        app = self.get_app()
        scale_app.delay(app, request.user, request.data)
        return Response(status=status.HTTP_204_NO_CONTENT)


class EventViewSet(AppFilterViewSet):
    model = models.app.App
    serializer_class = serializers.EventSerializer

    def list(self, request, **kwargs):
        ptype = request.query_params.get("ptype", None)
        pod_name = request.query_params.get("pod_name", None)
        if not any([ptype, pod_name]):
            data = []
        else:
            ref_kind, ref_name = "Deployment", f"{self.get_app().id}-{ptype}"
            if pod_name:
                ref_kind, ref_name = "Pod", pod_name
            events = self.get_app().list_events(ref_kind, ref_name)
            data = self.get_serializer(events, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)
