from .base import IngressClass, WildcardPathIngress
from .nginx import NginxIngress
from .traefik import TraefikIngress


# registry ingress class by controller
IngressClass.register("k8s.io/ingress-gce", WildcardPathIngress)
IngressClass.register("ingress.k8s.aws/alb", WildcardPathIngress)
IngressClass.register("traefik.io/ingress-controller", TraefikIngress)
IngressClass.register("k8s.io/ingress-nginx", NginxIngress)
