import logging
import hashlib
import threading
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError

from api.tasks import send_app_log
from api.utils import validate_json, validate_label
from api.exceptions import ServiceUnavailable
from scheduler import KubeException

from .base import AuditedModel, DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT


logger = logging.getLogger(__name__)

TLS_PROTOCOLS = ("HTTPS", "TLS")
HOSTNAME_PROTOCOLS = TLS_PROTOCOLS + ("HTTP", )


class LazySchemaValidator:
    """Defers schema import until validation time to avoid circular imports."""

    def __init__(self, module_path, attr_name):
        self.module_path = module_path
        self.attr_name = attr_name

    def __call__(self, value):
        mod = __import__(self.module_path, fromlist=[self.attr_name])
        validate_json(value, schema=getattr(mod, self.attr_name))


class Gateway(AuditedModel):
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    name = models.CharField(max_length=63, db_index=True, validators=[validate_label])
    ports = models.JSONField(
        default=list,
        validators=[LazySchemaValidator("api.serializers.schemas.gateway", "SCHEMA")],
    )

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this service.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        send_app_log.delay(self.app.id, message, level)
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
    def labels(self):
        return {"drycc.cc/gateway": self.name}

    @property
    def addresses(self):
        data = self.scheduler.gateways.get(self.app.id, self.name, ignore_exception=True)
        if data.status_code != 200:
            return []
        addresses = data.json()["status"].get("addresses", [])
        return addresses

    @property
    def listeners(self):
        listeners = []
        for item in self.ports:
            port, protocol = item["port"], item["protocol"]
            listener = {
                "name": f"{protocol.lower()}-{port}",
                "port": port,
                "protocol": protocol,
                "allowedRoutes": {"namespaces": {"from": "All"}},
            }
            if protocol == "TLS":
                listener["tls"] = {"mode": "Passthrough"}
            listeners.append(listener)
        return listeners

    def refresh_to_k8s(self):
        kwargs = {
            "listeners": self.listeners,
            "allowed_listeners": {"namespaces": {"from": "Same"}},
            "gateway_class": settings.DRYCC_APP_GATEWAY_CLASS
        }
        if self.app.tls_set.latest().certs_auto_enabled:
            kwargs["annotations"] = {"cert-manager.io/issuer": self.app.id}
        try:
            try:
                data = self.scheduler.gateways.get(self.app.id, self.name).json()
                if len(kwargs["listeners"]) > 0:
                    kwargs["version"] = data["metadata"]["resourceVersion"]
                    response = self.scheduler.gateways.patch(self.app.id, self.name, **kwargs)
                    if response.status_code == 409:
                        raise ServiceUnavailable(
                            f'Kubernetes gateway could not be patched: '
                            f'{response.status_code} {response.reason}'
                        )
                else:
                    logger.debug("delete k8s resource when listeners are empty")
                    self.scheduler.gateways.delete(
                        self.app.id, self.name, ignore_exception=True)
            except KubeException:
                if len(kwargs["listeners"]) > 0:
                    if "version" in kwargs:
                        kwargs.pop("version")
                    self.scheduler.gateways.create(self.app.id, self.name, **kwargs)
                else:
                    logger.debug("skip creating k8s resource when listeners are empty")
        except KubeException as e:
            raise ServiceUnavailable('Kubernetes gateway could not be created') from e
        for item in self.ports:
            if item["protocol"] in HOSTNAME_PROTOCOLS:
                self._refresh_listener_set(item["protocol"], item["port"])
        self._cleanup_unused_listener_sets()

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
        self.ports = []
        self._cleanup_unused_listener_sets()

        try:
            self.scheduler.gateways.delete(self.app.id, self.name, ignore_exception=False)
        except KubeException:
            self.log(
                'Kubernetes gateway cannot be deleted: {}'.format(self.name),
                level=logging.ERROR,
            )
        return super().delete(*args, **kwargs)

    def to_usage(self, timestamp: float):
        return [{
            "app_id": str(self.app_id),
            "workspace": self.app.workspace_id,
            "name": settings.DRYCC_APP_GATEWAY_CLASS,
            "type": "gateway",
            "unit": "number",
            "usage": 1,
            "kwargs": {
                "name": self.name,
            },
            "timestamp": int(timestamp),
            "identifier": hashlib.md5(self.name.encode("utf-8")).hexdigest(),
        }]

    def _check_port(self, port, protocol):
        for item in self.ports:
            if item["port"] == port:
                if (item["protocol"] == protocol) or (
                        item["protocol"] != "UDP" and protocol != "UDP"):
                    return False
        return True

    def _listener_set_name(self, protocol, port):
        return f"{self.name}-{protocol.lower()}-{port}"

    def _listener_entry_name(self, domain_str):
        return domain_str.replace(".", "-")

    def _cleanup_unused_listener_sets(self):
        expected = {
            self._listener_set_name(item["protocol"], item["port"])
            for item in self.ports
            if item["protocol"] in HOSTNAME_PROTOCOLS
        }
        try:
            response = self.scheduler.listenersets.get(self.app.id, labels=self.labels)
            for listener_set in response.json().get("items", []):
                listener_set_name = listener_set["metadata"]["name"]
                if listener_set_name not in expected:
                    self.scheduler.listenersets.delete(self.app.id, listener_set_name)
        except KubeException:
            self.log('Failed to list ListenerSets for cleanup', level=logging.WARN)

    def _refresh_listener_set(self, protocol, port):
        listener_set_name = self._listener_set_name(protocol, port)
        listeners = self._build_listener_set_listeners(protocol, port)
        if not listeners:
            self.scheduler.listenersets.delete(self.app.id, listener_set_name)
            return
        kwargs = {
            "listeners": listeners,
            "labels": self.labels,
            "parent_ref": {
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": self.name,
            },
        }

        auto_tls = self.app.tls_set.latest().certs_auto_enabled
        if auto_tls and protocol in TLS_PROTOCOLS:
            kwargs["annotations"] = {"cert-manager.io/issuer": self.app.id}
        try:
            try:
                data = self.scheduler.listenersets.get(self.app.id, listener_set_name).json()
                kwargs["version"] = data["metadata"]["resourceVersion"]
                response = self.scheduler.listenersets.patch(
                    self.app.id, listener_set_name, **kwargs
                )
                if response.status_code == 409:
                    self.log(
                        f'ListenerSet {listener_set_name} conflict during patch, please retry',
                        level=logging.WARN,
                    )
            except KubeException:
                if "version" in kwargs:
                    kwargs.pop("version")
                self.scheduler.listenersets.create(self.app.id, listener_set_name, **kwargs)
        except KubeException as e:
            raise ServiceUnavailable(
                f'ListenerSet {listener_set_name} could not be created/updated') from e

    def _build_listener_set_listeners(self, protocol, port):
        auto_tls = self.app.tls_set.latest().certs_auto_enabled
        listeners = []
        for domain in self.app.domain_set.all():
            listener = {
                "name": self._listener_entry_name(domain.domain),
                "port": port,
                "protocol": protocol,
                "hostname": domain.domain,
                "allowedRoutes": {"namespaces": {"from": "All"}},
            }
            if protocol in TLS_PROTOCOLS:
                secret_name = (
                    f"{self.app.id}-auto-tls" if auto_tls
                    else (domain.certificate.certname if domain.certificate else None)
                )
                if protocol == "TLS":
                    if secret_name:
                        listener["tls"] = {
                            "mode": "Terminate",
                            "certificateRefs": [{"kind": "Secret", "name": secret_name}],
                        }
                    else:
                        listener["tls"] = {"mode": "Passthrough"}
                elif secret_name:
                    listener["tls"] = {
                        "mode": "Terminate",
                        "certificateRefs": [{"kind": "Secret", "name": secret_name}],
                    }
            listeners.append(listener)
        return listeners

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
    kind = models.CharField(max_length=15, choices=[
        (key, '/'.join(value)) for key, value in PROTOCOLS_CHOICES.items()])
    name = models.CharField(max_length=63, db_index=True)
    rules = models.JSONField(
        default=list,
        validators=[LazySchemaValidator("api.serializers.schemas.rules", "SCHEMA")],
    )
    routable = models.BooleanField(default=True)
    parent_refs = models.JSONField(
        default=list,
        validators=[LazySchemaValidator("api.serializers.schemas.route", "PARENT_REFS_SCHEMA")],
    )

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

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this service.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        send_app_log.delay(self.app.id, message, level)
        logger.log(level, "[{}]: {}".format(self.app.id, message))

    def refresh_to_k8s(self):
        if self.routable:
            parent_refs, http_parent_refs = self._get_all_parent_refs()
            tls = self.app.tls_set.latest()
            if tls.https_enforced and self.kind == "HTTPRoute" and http_parent_refs:
                self._https_enforced_to_k8s(http_parent_refs)
            elif self.kind == "HTTPRoute":
                parent_refs.extend(http_parent_refs)
                self.scheduler.httproute.delete(self.app.id, self._https_redirect_name)
            else:
                parent_refs.extend(http_parent_refs)
            self._refresh_to_k8s(self.rules, parent_refs)
        else:
            self.scheduler.httproute.delete(self.app.id, self.name)
            self.scheduler.httproute.delete(self.app.id, self._https_redirect_name)

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
        if not self.cleaned_rules:
            msg = f"route {self.name} no available backend"
            self.log(msg, level=logging.ERROR)
            raise ValidationError(msg)
        self.rules = self.cleaned_rules
        super().save(*args, **kwargs)
        self.refresh_to_k8s()

    def delete(self, *args, **kwargs):
        try:
            k8s_route = getattr(self.scheduler, self.kind.lower())
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
            "parent_refs": parent_refs,
        }
        try:
            k8s_route = getattr(self.scheduler, self.kind.lower())
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
            "parent_refs": parent_refs,
        }
        try:
            try:
                data = self.scheduler.httproute.get(
                    self.app.id, self._https_redirect_name).json()
                manifest.update({"version": data["metadata"]["resourceVersion"]})
                self.scheduler.httproute.patch(
                    self.app.id, self._https_redirect_name, **manifest)
            except KubeException:
                self.scheduler.httproute.create(
                    self.app.id, self._https_redirect_name, **manifest)
        except KubeException as e:
            raise ServiceUnavailable(
                f'Kubernetes {self.kind.lower()} could not be created') from e

    def _get_all_parent_refs(self):
        gateways = {
            gateway.name: gateway
            for gateway in self.app.gateway_set.filter(
                name__in=[item["name"] for item in self.parent_refs])
        }
        domains = list(self.app.domain_set.filter(ptype__in=[s.ptype for s in self.services]))
        parent_refs, http_parent_refs = [], []
        for item in self.parent_refs:
            gateway_name, gateway_port = item["name"], item["port"]
            if gateway_name not in gateways:
                continue
            gateway = gateways[gateway_name]
            for port_info in gateway.ports:
                port, protocol = port_info["port"], port_info["protocol"]
                if port != gateway_port or self.kind.split("Route")[0] not in protocol:
                    continue
                if protocol in HOSTNAME_PROTOCOLS and domains:
                    listener_set_name = gateway._listener_set_name(protocol, port)
                    for domain in domains:
                        ref = {
                            "group": "gateway.networking.k8s.io",
                            "kind": "ListenerSet",
                            "name": listener_set_name,
                            "sectionName": gateway._listener_entry_name(domain.domain),
                        }
                        if protocol == "HTTP" and port == DEFAULT_HTTP_PORT:
                            http_parent_refs.append(ref)
                        else:
                            parent_refs.append(ref)
                else:
                    ref = {
                        "group": "gateway.networking.k8s.io",
                        "kind": "Gateway",
                        "name": gateway_name,
                        "sectionName": f"{protocol.lower()}-{port}",
                    }
                    if protocol == "HTTP" and port == DEFAULT_HTTP_PORT:
                        http_parent_refs.append(ref)
                    else:
                        parent_refs.append(ref)
        return parent_refs, http_parent_refs

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'name'), )
        ordering = ['-created']
