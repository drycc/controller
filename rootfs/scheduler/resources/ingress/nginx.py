from .base import (
    BaseIngress,
    MEM_REQUEST_BODY_BYTES,
    MAX_REQUEST_BODY_BYTES,
    MEM_RESPONSE_BODY_BYTES,
    MAX_RESPONSE_BODY_BYTES,
)


class NginxIngress(BaseIngress):

    def manifest(self, namespace, ingress, **kwargs):
        data = BaseIngress.manifest(self, namespace, ingress, **kwargs)
        data["metadata"]["annotations"].update({
            "nginx.ingress.kubernetes.io/client-body-buffer-size": MEM_REQUEST_BODY_BYTES,
            "nginx.ingress.kubernetes.io/proxy-body-size": MAX_REQUEST_BODY_BYTES,
            "nginx.ingress.kubernetes.io/proxy-buffering": "on",
            "nginx.ingress.kubernetes.io/proxy-buffer-size": MEM_RESPONSE_BODY_BYTES,
            "nginx.ingress.kubernetes.io/proxy-max-temp-file-size": (
                MAX_RESPONSE_BODY_BYTES - MEM_RESPONSE_BODY_BYTES
            ),
        })
        if "allowlist" in kwargs:
            allowlist = ", ".join(kwargs.pop("allowlist"))
            data["metadata"]["annotations"].update({
                "nginx.ingress.kubernetes.io/whitelist-source-range": allowlist
            })
        if "ssl_redirect" in kwargs:
            ssl_redirect = kwargs.pop("ssl_redirect")
            data["metadata"]["annotations"].update({
                "nginx.ingress.kubernetes.io/ssl-redirect": ssl_redirect
            })
        return data
