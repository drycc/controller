import logging
from django.db import models
from django.conf import settings
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
    ports = models.JSONField(default=list)

    def _check_port(self, port, protocol):
        for item in self.ports:
            if item["port"] == port:
                if (item["protocol"] == protocol) or (
                        item["protocol"] != "UDP" and protocol != "UDP"):
                    return False
        return True

    def _get_tls_domain(self, auto_tls):
        domains = self.app.domain_set.all()
        if not auto_tls:
            domains = domains.exclude(certificate=None)
        return domains

    def _get_listener_name(self, port, protocol, suffix=None):
        names = [self.app.id, str(port)]
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
            return False, {"detail": "port is occupied"}
        self.ports.append({"port": port, "protocol": protocol})
        return True, None

    def remove(self, port, protocol):
        ports = []
        for item in self.ports:
            if item["port"] != port or item["protocol"] != protocol:
                ports.append(item)
        if len(ports) == len(self.ports):
            return False, {"detail": "no matching listener exists"}
        self.ports = ports
        return True, ""

    @property
    def listeners(self):
        listeners = []
        auto_tls = self.app.tls_set.latest().certs_auto_enabled
        domains = list(self._get_tls_domain(auto_tls))
        for item in self.ports:
            port, protocol = item["port"], item["protocol"]
            if item["protocol"] in ("TLS", "HTTPS"):
                for domain in domains:
                    secret_name = (f"{self.app.id}-auto-tls" if
                                   auto_tls else domain.certificate.name)
                    listeners.append({
                        "allowedRoutes": {"namespaces": {"from": "All"}},
                        "name": self._get_listener_name(port, protocol, domain.domain),
                        "port": port,
                        "hostname": domain.domain,
                        "protocol": protocol,
                        "tls": {"certificateRefs": [{"kind": "Secret", "name": secret_name}]},
                    })
            else:
                listeners.append({
                    "allowedRoutes": {"namespaces": {"from": "All"}},
                    "name": self._get_listener_name(port, protocol),
                    "port": port,
                    "protocol": protocol,
                })
        return listeners

    def refresh_to_k8s(self):
        try:
            try:
                data = self._scheduler.gateways.get(self.app.id, self.name).json()
                if len(self.listeners) > 0:
                    self._scheduler.gateways.patch(self.app.id, self.name, **{
                        "listeners": self.listeners,
                        "gateway_class": settings.GATEWAY_CLASS,
                        "version": data["metadata"]["resourceVersion"],
                    })
                else:
                    logger.debug("delete k8s resource when listeners are empty")
                    self._scheduler.gateways.delete(
                        self.app.id, self.name, ignore_exception=True)
            except KubeException:
                if len(self.listeners) > 0:
                    self._scheduler.gateways.create(self.app.id, self.name, **{
                        "listeners": self.listeners,
                        "gateway_class": settings.GATEWAY_CLASS,
                    })
                else:
                    logger.debug("skip creating k8s resource when listeners are empty")
        except KubeException as e:
            raise ServiceUnavailable('Kubernetes gateway could not be created') from e

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.refresh_to_k8s()

    def delete(self, *args, **kwargs):
        try:
            self._scheduler.gateways.delete(self.app.id, self.name, ignore_exception=False)
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
    rules = models.JSONField(default=list)
    routable = models.BooleanField(default=True)
    parent_refs = models.JSONField(default=list)
    procfile_type = models.TextField()

    @property
    def protocols(self):
        if self.kind not in self.PROTOCOLS_CHOICES:
            raise NotImplementedError("this kind is not supported")
        return self.PROTOCOLS_CHOICES[self.kind]

    @property
    def default_rules(self):
        return [{"backendRefs": self.default_backend_refs}]

    @property
    def default_backend_refs(self):
        service = get_object_or_404(self.app.service_set, procfile_type=self.procfile_type)
        backend_refs = []
        for item in service.ports:
            if item["port"] == self.port:
                backend_refs.append({
                    "kind": "Service",
                    "name": str(service),
                    "port": item["port"],
                })
        return backend_refs

    def check_rules(self):
        service = self.app.service_set.filter(
            procfile_type=self.procfile_type).first()
        ports = [item["port"] for item in service.ports]
        for rule in self.rules:
            for backend_ref in rule["backendRefs"]:
                if backend_ref["name"] != str(service) or backend_ref["port"] not in ports:
                    return False, {"detail": "backendRefs associated with incorrect service"}
        return True, ""

    def refresh_to_k8s(self):
        parent_refs, http_parent_refs = self._get_all_parent_refs()
        tls = self.app.tls_set.latest()
        if tls.https_enforced and self.kind == "HTTPRoute":
            self._https_enforced_to_k8s(http_parent_refs)
        elif self.kind == "HTTPRoute":
            parent_refs.extend(http_parent_refs)
            self._scheduler.httproute.delete(self.app.id, f"{self.name}-https-redirect")
        else:
            parent_refs.extend(http_parent_refs)
        self._refresh_to_k8s(self.rules, parent_refs)

    def attach(self, gateway_name, port):
        ok, msg = self._check_parent(gateway_name, port)
        if not ok:
            return ok, msg
        parent_ref = {"name": gateway_name, "port": port}
        if parent_ref in self.parent_refs:
            return False, {"detail": "gateway and port already exist in this route"}
        else:
            self.parent_refs.append(parent_ref)
        return True, ""

    def detach(self, gateway_name, port):
        parent_ref = {"name": gateway_name, "port": port}
        if parent_ref in self.parent_refs:
            self.parent_refs.remove(parent_ref)
        else:
            return False, {"detail": "gateway and port do not exist in this route"}
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

    def _check_parent(self, gateway_name, port):
        try:
            gateway = self.app.gateway_set.filter(name=gateway_name).latest()
        except Gateway.DoesNotExist:
            return False, {"detail": f"this gateway {gateway_name} does not exist"}
        is_listener_allowed = False
        for gateway_port in gateway.ports:
            if port == gateway_port.get("port") and \
                    self.kind.split("Route")[0] in gateway_port.get("protocol"):
                is_listener_allowed = True
        if not is_listener_allowed:
            return False, {"detail": f"this gateway does not allow {self.kind} port {port} bind, \nplease add gateway listener first."}  # noqa
        for route in self.app.route_set.exclude(app=self.app, name=self.name):
            for parent_ref in route.parent_refs:
                if parent_ref["name"] == gateway_name and parent_ref["port"] == port:
                    for protocol in self.protocols:
                        if protocol in route.protocols:
                            return False, {"detail": "this listener has already been referenced"}
        return True, ""

    def _refresh_to_k8s(self, rules, parent_refs):
        try:
            k8s_route = getattr(self._scheduler, self.kind.lower())
            hostnames = [domain.domain for domain in self.app.domain_set.all()]
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

    def _get_all_parent_refs(self):
        gateways = {}
        for gateway in self.app.gateway_set.filter(
                name__in=[item["name"] for item in self.parent_refs]):
            gateways[gateway.name] = gateway
        parent_refs, http_parent_refs = [], []
        for item in self.parent_refs:
            gateway_name, port = item["name"], item["port"]
            if gateway_name not in gateways:
                continue
            gateway = gateways[gateway_name]
            for listener in gateway.listeners:
                if listener["port"] == port and listener["protocol"] in self.protocols:
                    parent_ref = {
                        "group": "gateway.networking.k8s.io",
                        "kind": "Gateway",
                        "name": gateway_name,
                        "sectionName": listener["name"],
                    }
                    if listener["protocol"] == "HTTP" and listener["port"] == 80:
                        http_parent_refs.append(parent_ref)
                    else:
                        parent_refs.append(parent_ref)
        return parent_refs, http_parent_refs

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'name'), )
        ordering = ['-created']
