import logging
import threading
from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.http import Http404

from api.exceptions import ServiceUnavailable
from scheduler import KubeException

from .base import AuditedModel, DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT

User = get_user_model()
logger = logging.getLogger(__name__)

TLS_PROTOCOLS = ("HTTPS", "TLS")
HOSTNAME_PROTOCOLS = TLS_PROTOCOLS + ("HTTP", )


class Gateway(AuditedModel):
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    name = models.CharField(max_length=63, db_index=True)
    ports = models.JSONField(default=list)

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this service.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.app.id, message))

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
    def addresses(self):
        data = self.scheduler().gateways.get(self.app.id, self.name, ignore_exception=True)
        if data.status_code != 200:
            return []
        addresses = data.json()["status"].get("addresses", [])
        return addresses

    @property
    def listeners(self):
        auto_tls = self.app.tls_set.latest().certs_auto_enabled
        listeners = []
        domains = list(self.app.domain_set.all())
        for item in self.ports:
            port, protocol = item["port"], item["protocol"]
            if item["protocol"] in HOSTNAME_PROTOCOLS:
                for domain in domains:
                    listener = {
                        "allowedRoutes": {"namespaces": {"from": "All"}},
                        "name": self._get_listener_name(port, protocol, domains.index(domain) + 1),
                        "port": port,
                        "hostname": domain.domain,
                        "protocol": protocol,
                    }
                    secret_name = f"{self.app.id}-auto-tls" if auto_tls else (
                        domain.certificate.certname if domain.certificate else None)
                    if secret_name and protocol in TLS_PROTOCOLS:
                        listener["tls"] = {
                            "certificateRefs": [{"kind": "Secret", "name": secret_name}]}
                    listeners.append(listener)
            if protocol not in TLS_PROTOCOLS:
                listeners.append({
                    "allowedRoutes": {"namespaces": {"from": "All"}},
                    "name": self._get_listener_name(port, protocol, 0),
                    "port": port,
                    "protocol": protocol,
                })
        return listeners

    def refresh_to_k8s(self):
        kwargs = {"listeners": self.listeners, "gateway_class": settings.GATEWAY_CLASS}
        if self.app.tls_set.latest().certs_auto_enabled:
            kwargs["annotations"] = {"cert-manager.io/issuer": self.app.id}
        try:
            try:
                data = self.scheduler().gateways.get(self.app.id, self.name).json()
                if len(kwargs["listeners"]) > 0:
                    kwargs["version"] = data["metadata"]["resourceVersion"]
                    self.scheduler().gateways.patch(self.app.id, self.name, **kwargs)
                else:
                    logger.debug("delete k8s resource when listeners are empty")
                    self.scheduler().gateways.delete(
                        self.app.id, self.name, ignore_exception=True)
            except KubeException:
                if len(kwargs["listeners"]) > 0:
                    self.scheduler().gateways.create(self.app.id, self.name, **kwargs)
                else:
                    logger.debug("skip creating k8s resource when listeners are empty")
        except KubeException as e:
            raise ServiceUnavailable('Kubernetes gateway could not be created') from e

    def change_default_tls(self):
        if self.name != self.app.id:
            return False
        tls_enabled = (self.app.tls_set.latest().certs_auto_enabled and
                       self.app.domain_set.exists()) or self.app.domain_set.filter(
                           models.Q(certificate__isnull=False)).exists()
        if tls_enabled:
            return self.add(DEFAULT_HTTPS_PORT, "HTTPS")[0]
        return self.remove(DEFAULT_HTTPS_PORT, "HTTPS")[0]

    def save(self, *args, **kwargs):
        self.change_default_tls()
        super().save(*args, **kwargs)
        self.refresh_to_k8s()

    def delete(self, *args, **kwargs):
        try:
            self.scheduler().gateways.delete(self.app.id, self.name, ignore_exception=False)
        except KubeException:
            self.log(
                'Kubernetes gateway cannot be deleted: {}'.format(self.name),
                level=logging.ERROR,
            )
        return super().delete(*args, **kwargs)

    def _check_port(self, port, protocol):
        for item in self.ports:
            if item["port"] == port:
                if (item["protocol"] == protocol) or (
                        item["protocol"] != "UDP" and protocol != "UDP"):
                    return False
        return True

    def _get_listener_name(self, port, protocol, index):
        if protocol in ("TCP", "TLS", "HTTP"):
            protocol = "TCP"
        elif protocol in ("HTTPS", ):
            protocol = "MIX"
        else:
            protocol = "UDP"
        return "-".join([protocol, str(port), str(index)]).lower()

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'name'), )
        ordering = ['-created']


class Route(AuditedModel):
    CACHE = threading.local()
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
    rules = models.JSONField(default=list)
    routable = models.BooleanField(default=True)
    parent_refs = models.JSONField(default=list)

    @property
    def services(self):
        key = f"{self.app.id}_{self.name}"
        if not hasattr(self.CACHE, key):
            service_names = set()
            for rule in self.rules:
                for backend in rule['backendRefs']:
                    service_names.add(backend['name'])
            setattr(self.CACHE, key,
                    [s for s in self.app.service_set.all() if s.name in service_names])
        return getattr(self.CACHE, key)

    @property
    def protocols(self):
        if self.kind not in self.PROTOCOLS_CHOICES:
            raise NotImplementedError("this kind is not supported")
        return self.PROTOCOLS_CHOICES[self.kind]

    @property
    def hostnames(self):
        return [domain.domain for domain in self.app.domain_set.filter(
                ptype__in=[s.ptype for s in self.services])]

    @property
    def cleaned_rules(self):
        services, rules = self.services, []
        for rule in self.rules:
            backend_refs = []
            for backend_ref in rule["backendRefs"]:
                for service in services:
                    ports = [item["port"] for item in service.ports]
                    if backend_ref["port"] in ports and backend_ref["name"] == service.name:
                        backend_refs.append(backend_ref)
            if backend_refs:
                rule['backendRefs'] = backend_refs
                rules.append(rule)
        return rules

    @property
    def tls_force_hostnames(self):
        tls = self.app.tls_set.latest()
        q = Q(ptype__int=[s.ptype for s in self.services])
        if not tls.certs_auto_enabled:
            q &= Q(certificate__isnull=False)
        domains = self.app.domain_set.filter(q)
        return [domain.domain for domain in domains]

    def check_rules(self, rules):
        for rule in rules:
            for backend_ref in rule["backendRefs"]:
                kind = backend_ref.get("kind", "Service")
                if kind != "Service":
                    return False, {"detail": "BackendRef only supports service kind"}
                has_service = False
                for service in self.services:
                    ports = [item["port"] for item in service.ports]
                    if backend_ref["port"] in ports and backend_ref["name"] == service.name:
                        has_service = True
                        break
                if not has_service:
                    msg = f"service {backend_ref['name']}:{backend_ref['port']} does not exist"
                    return False, {"detail": msg}
        return True, ""

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this service.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.app.id, message))

    def refresh_to_k8s(self):
        if self.routable:
            parent_refs, http_parent_refs = self._get_all_parent_refs()
            tls = self.app.tls_set.latest()
            if tls.https_enforced and self.kind == "HTTPRoute":
                self._https_enforced_to_k8s(http_parent_refs)
            elif self.kind == "HTTPRoute":
                parent_refs.extend(http_parent_refs)
                self.scheduler().httproute.delete(self.app.id, self._https_redirect_name)
            else:
                parent_refs.extend(http_parent_refs)
            self._refresh_to_k8s(self.rules, parent_refs)
        else:
            self.scheduler().httproute.delete(self.app.id, self.name)
            self.scheduler().httproute.delete(self.app.id, self._https_redirect_name)

    def change_default_tls(self):
        if self.app.id != self.name:
            return False
        tls_enabled = (self.app.tls_set.latest().certs_auto_enabled and
                       self.app.domain_set.exists()) or self.app.domain_set.filter(
                           models.Q(certificate__isnull=False)).exists()
        if tls_enabled:
            return self.attach(self.app.id, DEFAULT_HTTPS_PORT)[0]
        else:
            return self.detach(self.app.id, DEFAULT_HTTPS_PORT)[0]

    def attach(self, gateway_name, port):
        ok, msg = self._check_parent(gateway_name, port)
        if not ok:
            return ok, {"detail": msg}
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
        self.change_default_tls()
        cleaned_rules = self.cleaned_rules
        if not cleaned_rules:
            msg = f"route {self.name} no available backend"
            self.log(msg, level=logging.ERROR)
            raise Http404(msg)
        self.rules = cleaned_rules
        super().save(*args, **kwargs)
        self.refresh_to_k8s()

    def delete(self, *args, **kwargs):
        try:
            k8s_route = getattr(self.scheduler(), self.kind.lower())
            k8s_route.delete(self.app.id, self.name, ignore_exception=False)
        except KubeException:
            self.log(
                'Kubernetes {} cannot be deleted: {}'.format(self.kind.lower(), self.name),
                level=logging.ERROR,
            )
        return super().delete(*args, **kwargs)

    @property
    def _https_redirect_name(self):
        return f"{self.name}-https-redirect"

    def _check_parent(self, gateway_name, port):
        try:
            gateway = self.app.gateway_set.filter(name=gateway_name).latest()
        except Gateway.DoesNotExist:
            return False, f"this gateway {gateway_name} does not exist"
        is_listener_allowed = False
        for gateway_port in gateway.ports:
            if port == gateway_port.get("port") and \
                    self.kind.split("Route")[0] in gateway_port.get("protocol"):
                is_listener_allowed = True
        if not is_listener_allowed:
            return False, "listener does not exist, please add gateway listener first."
        for route in self.app.route_set.exclude(app=self.app, name=self.name):
            for parent_ref in route.parent_refs:
                if parent_ref["name"] == gateway_name and parent_ref["port"] == port:
                    if not set(route.protocols).issubset(HOSTNAME_PROTOCOLS) and (
                            set(route.protocols).issubset(self.protocols) or
                            set(self.protocols).issubset(route.protocols)):
                        return False, "this listener has already been referenced"
        return True, ""

    def _refresh_to_k8s(self, rules, parent_refs):
        manifest = {
            "rules": rules,
            "hostnames": self.hostnames,
            "parent_refs": parent_refs,
        }
        try:
            k8s_route = getattr(self.scheduler(), self.kind.lower())
            try:
                data = k8s_route.get(self.app.id, self.name).json()
                manifest.update({"version": data["metadata"]["resourceVersion"]})
                k8s_route.patch(self.app.id, self.name, **manifest)
            except KubeException:
                k8s_route.create(self.app.id, self.name, **manifest)
        except KubeException as e:
            raise ServiceUnavailable(
                f'Kubernetes {self.kind.lower()} could not be created') from e

    def _https_enforced_to_k8s(self, parent_refs):
        manifest = {
            "rules": [{
                "filters": [{
                    "type": "RequestRedirect",
                    "requestRedirect": {
                        "port": DEFAULT_HTTPS_PORT, "scheme": "https", "statusCode": 301
                    }
                }]
            }],
            "hostnames": self.tls_force_hostnames,
            "parent_refs": parent_refs,
        }
        try:
            try:
                data = self.scheduler().httproute.get(
                    self.app.id, self._https_redirect_name).json()
                manifest.update({"version": data["metadata"]["resourceVersion"]})
                self.scheduler().httproute.patch(
                    self.app.id, self._https_redirect_name, **manifest)
            except KubeException:
                self.scheduler().httproute.create(
                    self.app.id, self._https_redirect_name, **manifest)
        except KubeException as e:
            raise ServiceUnavailable(
                f'Kubernetes {self.kind.lower()} could not be created') from e

    def _get_all_parent_refs(self):
        gateways = {}
        for gateway in self.app.gateway_set.filter(
                name__in=[item["name"] for item in self.parent_refs]):
            gateways[gateway.name] = gateway
        hostnames, parent_refs, http_parent_refs = self.hostnames, [], []
        for item in self.parent_refs:
            gateway_name, port = item["name"], item["port"]
            if gateway_name not in gateways:
                continue
            gateway = gateways[gateway_name]
            for listener in gateway.listeners:
                hostname = listener.get('hostname', None)
                if listener["port"] == port and listener["protocol"] in self.protocols and (
                        hostname is None or hostname in hostnames):
                    parent_ref = {
                        "group": "gateway.networking.k8s.io",
                        "kind": "Gateway",
                        "name": gateway_name,
                        "sectionName": listener["name"],
                    }
                    if listener["protocol"] == "HTTP" and listener["port"] == DEFAULT_HTTP_PORT:
                        http_parent_refs.append(parent_ref)
                    else:
                        parent_refs.append(parent_ref)
        return parent_refs, http_parent_refs

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'name'), )
        ordering = ['-created']
