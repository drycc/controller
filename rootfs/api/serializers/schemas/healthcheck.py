SCHEMA = {
    "$schema": "http://json-schema.org/schema#",

    "type": "object",
    "properties": {
        # Exec specifies the action to take.
        # More info: http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_execaction
        "exec": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"}
                }
            },
            "required": ["command"]
        },
        # HTTPGet specifies the http request to perform.
        # More info: http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_httpgetaction
        "httpGet": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "port": {"type": "integer"},
                "host": {"type": "string"},
                "scheme": {"type": "string"},
                "httpHeaders": {
                    "type": "array",
                    "minItems": 0,
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "value": {"type": "string"},
                        }
                    }
                }
            },
            "required": ["port"]
        },
        # TCPSocket specifies an action involving a TCP port.
        # More info: http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_tcpsocketaction
        "tcpSocket": {
            "type": "object",
            "properties": {
                "port": {"type": "integer"},
            },
            "required": ["port"]
        },
        # Number of seconds after the container has started before liveness probes are initiated.
        # More info: http://releases.k8s.io/HEAD/docs/user-guide/pod-states.md#container-probes
        "initialDelaySeconds": {"type": "integer"},
        # Number of seconds after which the probe times out.
        # More info: http://releases.k8s.io/HEAD/docs/user-guide/pod-states.md#container-probes
        "timeoutSeconds": {"type": "integer"},
        # How often (in seconds) to perform the probe.
        "periodSeconds": {"type": "integer"},
        # Minimum consecutive successes for the probe to be considered successful
        # after having failed.
        "successThreshold": {"type": "integer"},
        # Minimum consecutive failures for the probe to be considered
        # failed after having succeeded.
        "failureThreshold": {"type": "integer"},
    }
}
