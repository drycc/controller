PROCTYPE_REGEX = r'^(?P<type>[a-z0-9]+(\-[a-z0-9]+)*)(?<!-canary)$'

SCHEMA = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "build": {
            "type": "object",
            "properties": {
                "docker": {
                    "type": "object",
                    "patternProperties": {
                        PROCTYPE_REGEX: {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                "config": {"type": "object"}
            },
        },
        "run": {
            "type": "object",
            "properties": {
                "image": {"type": "string"},
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                }
            },
        },
        "deploy": {
            "type": "object",
            "patternProperties": {
                PROCTYPE_REGEX: {
                    "properties": {
                        "image": {"type": "string"},
                        "command": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "args": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    }
                },
            },
            "minProperties": 1,
            "additionalProperties": False,
        },
    },
    "required": ["deploy"],
}
