import logging
from django.db import models
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

from api.exceptions import ServiceUnavailable
from scheduler import KubeException

from .base import AuditedModel

User = get_user_model()
logger = logging.getLogger(__name__)


class Gateway(AuditedModel):
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    name = models.CharField(max_length=63, db_index=True)
    listeners = models.JSONField(default=dict)

    def _check_port(self, port, protocol):
        for listener in self.listeners:
            if listener.port == port:
                if (listener["protocol"] == protocol) or (
                        listener["protocol"] != "UDP" and protocol != "UDP"):
                    return False
        return True

    def _get_tls_domain(self, auto_tls):
        domains = self.app.domain_set
        if not auto_tls:
            domains = domains.exclude(certificate=None)
        return domains

    def _get_listener_name(self, port, protocol, suffix=None):
        names = [self.app.id, port]
        if protocol in ("TCP", "TLS", "HTTP"):
            names.append("TCP")
        elif protocol in ("HTTPS", ):
            names.append("MIX")
        else:
            names.append("UDP")
        if suffix:
            names.append(suffix)
        return "-".join(names).lower()

    def add(self, port, protocol):
        # check port
        if not self._check_port(port, protocol):
            return False, "port is occupied"
        listeners = []
        auto_tls = self.app.tls_set.latest().certs_auto_enabled
        if protocol in ("TLS", "HTTPS"):
            for domain in self._get_tls_domain(auto_tls):
                secret_name = f"{self.app.id}-auto-tls" if auto_tls else domain.certificate.name
                listeners.append({
                    "allowedRoutes": {"namespaces": {"from": "All"}},
                    "name": self._get_listener_name(port, protocol, domain.domain),
                    "port": port,
                    "hostname": domain.domain,
                    "protocol": protocol,
                    "tls": {"certificateRefs": [{"kind": "Secret", "name": secret_name}]},
                })
            if len(listeners) == 0:
                return False, "no matching certificate exists"
        else:
            listeners.append({
                "allowedRoutes": {"namespaces": {"from": "All"}},
                "name": self._get_listener_name(port, protocol),
                "port": port,
                "protocol": protocol,
            })
        self.listeners.extend(listeners)
        return True, None

    def remove(self, port, protocol):
        listeners = []
        for listener in self.listeners:
            if listener["port"] == port and listener["protocol"] == protocol:
                for route in self.app.route_set:
                    for parent_ref in route.parent_refs:
                        if (parent_ref["name"] == self.name
                                and parent_ref["sectionName"] == listener["name"]):
                            return False, "cannot delete a referenced listener"
            else:
                listeners.append(listener)
        if len(listeners) == len(self.listeners):
            return False, "no matching listener exists"
        self.listeners = listeners
        return True, ""

    def refresh_to_k8s(self):
        try:
            try:
                data = self._scheduler.gateway.get(self.app.id, self.name).json()
                self._scheduler.gateway.patch(self.app.id, self.name, **{
                    "listeners": self.listeners,
                    "version": data["metadata"]["resourceVersion"],
                })
            except KubeException:
                self._scheduler.gateway.create(self.app.id, self.name, **{
                    "listeners": self.listeners,
                })
        except KubeException as e:
            raise ServiceUnavailable('Kubernetes gateway could not be created') from e

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.refresh_to_k8s()

    def delete(self, *args, **kwargs):
        try:
            self._scheduler.gateway.delete(self.app.id, self.name, ignore_exception=False)
        except KubeException:
            logger.log(
                msg='Kubernetes gateway cannot be deleted: {}'.format(self.name),
                level=logging.ERROR,
            )
        return super().delete(*args, **kwargs)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'name'), )
        ordering = ['-created']


class Route(AuditedModel):
    PROTOCOLS_CHOICES = {
        "TLSRoute": ("TCP", ),
        "TCPRoute": ("TCP", ),
        "UDPRoute": ("UDP", ),
        "GRPCRoute": ("HTTPS", ),
        "HTTPRoute": ("HTTP", "HTTPS"),
    }

    app = models.ForeignKey('App', on_delete=models.CASCADE)
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    kind = models.CharField(max_length=15, choices=[
        (key, '/'.join(value)) for key, value in PROTOCOLS_CHOICES.items()])
    name = models.CharField(max_length=63, db_index=True)
    port = models.PositiveIntegerField()
    rules = models.JSONField(default=dict)
    routable = models.BooleanField(default=True)
    parent_refs = models.JSONField(default=dict)
    procfile_type = models.TextField()

    @property
    def protocols(self):
        if self.kind not in self.PROTOCOLS_CHOICES:
            raise NotImplementedError("this kind is not supported")
        return self.PROTOCOLS_CHOICES[self.kind]

    def _check_parent(self, parent):
        for parent_ref in self.parent_refs:
            if parent_ref["name"] == parent["name"]:
                if parent["sectionName"] == parent_ref["sectionName"]:
                    return False, "this listener already exists"
        for route in self.app.route_set.exclude(app=self.app, name=self.name):
            for parent_ref in route.parent_refs:
                if (parent_ref["name"] == parent["name"]
                        and parent["sectionName"] == parent_ref["sectionName"]):
                    return False, "this listener has already been referenced"
        return True, ""

    def _get_parent_refs(self, gateway_name, port):
        gateway = get_object_or_404(self.app.gateway_set, name=gateway_name)
        parent_refs = []
        for listener in gateway.listeners:
            if listener["port"] == port and listener["protocol"] in self.protocols:
                parent_ref = {
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "name": gateway_name,
                    "sectionName": listener["name"],
                }
                ok, msg = self._check_parent(parent_ref)
                if not ok:
                    return parent_refs, msg
                parent_refs.append(parent_ref)
        return parent_refs, ""

    def _remove_parent_refs(self, gateway_name, port):
        gateway = get_object_or_404(self.app.gateway_set, name=gateway_name)
        section_names = []
        for listener in gateway.listeners:
            if listener["port"] == port and listener["protocol"] in self.protocols:
                section_names.append(listener["name"])
        parent_refs = []
        for parent_ref in self.parent_refs:
            if (parent_ref["name"] != gateway_name or
                    parent_ref["sectionName"] not in section_names):
                parent_refs.append(parent_ref)
        if len(parent_refs) == len(self.parent_refs):
            return parent_refs, "no matching listener exists"
        return parent_refs, ""

    def check_rules(self):
        service = self.app.service_set.filter(
            procfile_type=self.procfile_type).first()
        ports = [item["port"] for item in service.ports]
        for rule in self.rules:
            for backend_ref in rule["backendRefs"]:
                if backend_ref["name"] != str(service) or backend_ref["port"] not in ports:
                    return False, "backendRefs associated with incorrect service"
        return True, ""

    def get_backend_refs(self):
        service = self.app.service_set.filter(
            procfile_type=self.procfile_type).first()
        backend_refs = []
        for item in service.ports:
            if item["port"] == self.port:
                backend_refs.append({
                    "kind": "Service",
                    "name": str(service),
                    "port": item["port"],
                })
        return backend_refs

    def _https_enforced_to_k8s(self, parent_refs):
        rules = {
            "filters": [{
                "type": "RequestRedirect",
                "requestRedirect": {"port": 443, "scheme": "https", "statusCode": 301}
            }]
        }
        route_name = f"{self.name}-https-redirect"
        try:
            if not self.routable:
                self._scheduler.httproute.delete(self.app.id, route_name)
            else:
                try:
                    data = self._scheduler.httproute.get(self.app.id, route_name).json()
                    self._scheduler.httproute.patch(self.app.id, route_name, **{
                        "rules": rules,
                        "parent_refs": parent_refs,
                        "version": data["metadata"]["resourceVersion"],
                    })
                except KubeException:
                    self._scheduler.httproute.create(self.app.id, route_name, **{
                        "rules": rules,
                        "parent_refs": parent_refs,
                    })
        except KubeException as e:
            raise ServiceUnavailable(
                f'Kubernetes {self.kind.lower()} could not be created') from e

    def _refresh_to_k8s(self, parent_refs, rules):
        try:
            k8s_route = getattr(self._scheduler, self.kind.lower())
            hostnames = [domain.domain for domain in self.app.domain_set]
            try:
                data = k8s_route.get(self.app.id, self.name).json()
                k8s_route.patch(self.app.id, self.name, **{
                    "rules": rules,
                    "hostnames": hostnames,
                    "parent_refs": parent_refs,
                    "version": data["metadata"]["resourceVersion"],
                })
            except KubeException:
                k8s_route.create(self.app.id, self.name, **{
                    "rules": rules,
                    "hostnames": hostnames,
                    "parent_refs": parent_refs,
                })
        except KubeException as e:
            raise ServiceUnavailable(
                f'Kubernetes {self.kind.lower()} could not be created') from e

    def refresh_to_k8s(self):
        parent_refs = self.parent_refs
        https_enforced = self.app.tls_set.latest()
        if https_enforced and self.kind == "HTTPRoute":
            http_parent_refs = []
            for gateway in self.app.gateway_set.filter(
                    name__in=set([parent_ref["name"] for parent_ref in parent_refs])):
                for listener in gateway.listeners:
                    if listener["protocol"] == "HTTP" and listener["port"] == 80:
                        for parent_ref in self.parent_refs:
                            if (parent_ref["name"] == gateway.name
                                    and parent_ref["sectionName"] == listener["name"]):
                                http_parent_refs.append(parent_ref)
            self._https_enforced_to_k8s(http_parent_refs)
            parent_refs = list(set(parent_refs).difference(http_parent_refs))
        elif self.kind == "HTTPRoute":
            self._scheduler.httproute.delete(self.app.id, f"{self.name}-https-redirect")
        self._refresh_to_k8s(self.rules, parent_refs)

    def attach(self, gateway_name, port):
        parent_refs, msg = self._get_parent_refs(port, gateway_name)
        if len(parent_refs) == 0:
            return False, msg if msg else "no matching listener exists"
        self.parent_refs.extend(parent_refs)
        return True, ""

    def detach(self, gateway_name, port):
        parent_refs, msg = self._remove_parent_refs(port, gateway_name)
        if msg:
            return False, msg
        self.parent_refs = parent_refs
        return True, ""

    def save(self, *args, **kwargs):
        ok, msg = self.check_rules()
        if not ok:
            raise ValueError(msg)
        super().save(*args, **kwargs)
        self.refresh_to_k8s()

    def delete(self, *args, **kwargs):
        try:
            k8s_route = getattr(self._scheduler, self.kind.lower())
            k8s_route.delete(self.app.id, self.name, ignore_exception=False)
        except KubeException:
            logger.log(
                msg='Kubernetes {} cannot be deleted: {}'.format(self.kind.lower(), self.name),
                level=logging.ERROR,
            )
        return super().delete(*args, **kwargs)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'name'), )
        ordering = ['-created']
