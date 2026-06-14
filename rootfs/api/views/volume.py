"""
Volume views.
"""
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response

from api import models, serializers
from api.exceptions import DryccException
from api.views.app import AppFilterViewSet
from api.tasks import mount_app


class AppVolumesViewSet(AppFilterViewSet):
    """RESTful views for volumes apps with collaborators."""
    model = models.volume.Volume
    serializer_class = serializers.VolumeSerializer

    def get_object(self):
        return get_object_or_404(models.volume.Volume,
                                 app__id=self.kwargs['id'],
                                 name=self.kwargs['name'])

    def expand(self, request, **kwargs):
        size, volume = request.data['size'], self.get_object()
        if volume.type == "csi":
            from api import utils
            if utils.unit_to_bytes(request.data['size']) < utils.unit_to_bytes(volume.size):
                raise DryccException('Shrink volume is not supported.')
            volume.size = size
            volume.save()
            serializer = self.get_serializer(volume, many=False)
            return Response(serializer.data)
        raise DryccException(f'{volume.type} volume is not support expand.')

    def destroy(self, request, **kwargs):
        volume = self.get_object()
        app = self.get_app()
        is_subset = set(volume.path.keys()).issubset(set(app.ptypes))
        if volume.path != {} and is_subset:
            raise DryccException("this volume is mounting")
        volume.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def path(self, request, *args, **kwargs):
        path = request.data.get('path')
        if path is None:
            raise DryccException("path is a required field")
        else:
            path = serializers.VolumeSerializer().validate_path(path)
        volume = self.get_object()
        ptypes = [_ for _ in path.keys() if _ not in volume.app.ptypes]
        if ptypes:
            raise DryccException("process type {} is not included in procfile".
                                 format(','.join(ptypes)))
        if set(path.items()).issubset(set(volume.path.items())):
            raise DryccException("mount path not changed")
        volume.check_path(path)

        app = self.get_app()
        mount_app.delay(app, self.request.user, volume, path)
        serializer = self.get_serializer(volume, many=False)
        return Response(serializer.data)
