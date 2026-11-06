"""
Settings, domain, and certificate views.
"""
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.http import Http404
from rest_framework import status
from rest_framework.response import Response

from api import models, serializers
from api.exceptions import DryccException
from api.views.app import AppFilterViewSet


class AppSettingsViewSet(AppFilterViewSet):
    model = models.appsettings.AppSettings
    serializer_class = serializers.AppSettingsSerializer


class DomainViewSet(AppFilterViewSet):
    """A viewset for interacting with Domain objects."""
    model = models.domain.Domain
    serializer_class = serializers.DomainSerializer

    def get_object(self, **kwargs):
        qs = self.get_queryset(**kwargs)
        domain = self.kwargs['domain']
        # support IDN domains, i.e. accept Unicode encoding too
        try:
            import idna
            if domain.startswith("*."):
                ace_domain = "*." + idna.encode(domain[2:]).decode("utf-8", "strict")
            else:
                ace_domain = idna.encode(domain).decode("utf-8", "strict")
        except:  # noqa
            ace_domain = domain
        return get_object_or_404(qs, domain=ace_domain)

    def destroy(self, request, **kwargs):
        domain = self.get_object()
        domain.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ServiceViewSet(AppFilterViewSet):
    """A viewset for interacting with Service objects."""
    model = models.service.Service
    serializer_class = serializers.ServiceSerializer

    def get_object(self):
        return get_object_or_404(self.get_app().service_set, ptype=self.kwargs["ptype"])

    @transaction.atomic
    def upsert(self, request, **kwargs):
        app = self.get_app()
        ptype = self.get_serializer().validate_ptype(kwargs["ptype"])
        service = app.service_set.filter(ptype=ptype).first()
        created = service is None
        serializer = self.get_serializer(instance=service, data=request.data)
        serializer.is_valid(raise_exception=True)
        service = serializer.save(app=app, ptype=ptype)
        http_status = (
            status.HTTP_201_CREATED if created else status.HTTP_200_OK)
        return Response(self.get_serializer(service).data, status=http_status)


class CertificateViewSet(AppFilterViewSet):
    """A viewset for interacting with Certificate objects."""
    model = models.certificate.Certificate
    serializer_class = serializers.CertificateSerializer

    def get_object(self, **kwargs):
        """Retrieve domain certificate by its name"""
        qs = self.get_queryset(**kwargs)
        return get_object_or_404(qs, name=self.kwargs['name'])

    def attach(self, request, *args, **kwargs):
        try:
            if "domain" not in kwargs and not request.data.get('domain'):
                raise DryccException("domain is a required field")
            elif request.data.get('domain'):
                kwargs['domain'] = request.data['domain']

            self.get_object().attach(*args, **kwargs)
        except Http404:
            raise

        return Response(status=status.HTTP_201_CREATED)

    def detach(self, request, *args, **kwargs):
        try:
            self.get_object().detach(*args, **kwargs)
        except Http404:
            raise
        return Response(status=status.HTTP_204_NO_CONTENT)


class TLSViewSet(AppFilterViewSet):
    model = models.tls.TLS
    serializer_class = serializers.TLSSerializer

    def events(self, request, **kwargs):
        results = self.get_object().events()
        return Response({'results': results, 'count': len(results)})
