from .base import IngressFactory, WildcardPathIngress
from .nginx import NginxIngress
from .traefik import TraefikIngress


IngressFactory.register("gce", WildcardPathIngress)
IngressFactory.register("alb", WildcardPathIngress)
IngressFactory.register("traefik", TraefikIngress)
IngressFactory.register("nginx", NginxIngress)
