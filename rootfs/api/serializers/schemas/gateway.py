PORT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["port", "protocol"],
    "properties": {
        "port": {
            "type": "integer",
            "minimum": 1,
            "maximum": 65535,
        },
        "protocol": {
            "type": "string",
            "enum": ["HTTP", "HTTPS", "TCP", "UDP", "TLS"],
        },
    },
}


SCHEMA = {
    "$schema": "http://json-schema.org/schema#",
    "type": "array",
    "items": PORT_SCHEMA,
}
