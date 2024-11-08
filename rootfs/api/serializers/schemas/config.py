SCHEMA = {
    "description": "Config values are a list of config item.",
    "$schema": "http://json-schema.org/schema#",
    "items": {
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "ptype": {"type": "string"},
                    "value": {"oneOf": [{"type": "string"}, {"type": "null"}]},
                },
                "required": ["name", "ptype", "value"],
                "additionalProperties": False,
            },
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "group": {"type": "string"},
                    "value": {"oneOf": [{"type": "string"}, {"type": "null"}]},
                },
                "required": ["name", "group", "value"],
                "additionalProperties": False,
            },
        ]
    },
    "minItems": 0,
    "type": "array"
}
