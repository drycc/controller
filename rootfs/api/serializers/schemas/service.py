PORT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["port", "protocol", "targetPort"],
    "properties": {
        "port": {
            "type": "integer",
            "minimum": 1,
            "maximum": 65535,
        },
        "protocol": {
            "type": "string",
            "enum": ["TCP", "UDP", "SCTP"],
        },
        "targetPort": {
            "type": "integer",
            "minimum": 1,
            "maximum": 65535,
        },
    },
}


SCHEMA = {
    "$schema": "http://json-schema.org/schema#",
    "type": "array",
    "minItems": 1,
    "items": PORT_SCHEMA,
}
