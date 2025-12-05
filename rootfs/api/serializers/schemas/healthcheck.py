SCHEMA = {
    "$schema": "http://json-schema.org/schema#",

    "type": "object",
    "properties": {
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
        "grpc": {
            "type": "object",
            "properties": {
                "port": {"type": "integer"},
                "service": {"type": "string"},
            },
            "required": ["port"]
        },
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
        "tcpSocket": {
            "type": "object",
            "properties": {
                "port": {"type": "integer"},
            },
            "required": ["port"]
        },
        "initialDelaySeconds": {"type": "integer"},
        "timeoutSeconds": {"type": "integer"},
        "periodSeconds": {"type": "integer"},
        "successThreshold": {"type": "integer"},
        "failureThreshold": {"type": "integer"},
    },
    "oneOf": [
        {"required": ["exec"]},
        {"required": ["grpc"]},
        {"required": ["httpGet"]},
        {"required": ["tcpSocket"]},
    ]
}
