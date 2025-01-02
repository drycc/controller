
FILENAME_REGEX = r'^(?P<name>[a-z0-9]+(\.[a-z0-9]+)*)$'
PROCTYPE_REGEX = r'^(?P<type>[a-z0-9]+(\-[a-z0-9]+)*)$'
CONFIGKEY_REGEX = r'^[A-z0-9_\-\.]+$'
CONFIGENV_SCHEMA = {
    "type": "object",
    "patternProperties": {
        CONFIGKEY_REGEX: {"type": "string"},
    },
}
SCHEMA = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "config": {
            "type": "object",
            "patternProperties": {
                FILENAME_REGEX: CONFIGENV_SCHEMA,
            },
        },
        "pipeline": {
            "type": "object",
            "patternProperties": {
                FILENAME_REGEX: {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "pattern": "^pipeline$"},
                        "ptype": {"type": "string", "pattern": PROCTYPE_REGEX},
                        "build": {
                            "type": "object",
                            "properties": {
                                "docker": {"type": "string"},
                                "arg": CONFIGENV_SCHEMA,
                            },
                            "additionalProperties": False,
                        },
                        "env": CONFIGENV_SCHEMA,
                        "run": {
                            "type": "object",
                            "properties": {
                                "command": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "args": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "image": {"type": "string"},
                                "timeout": {"type": "integer"},
                            },
                            "additionalProperties": False,
                        },
                        "config": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "pattern": FILENAME_REGEX,
                            },
                        },
                        "deploy": {
                            "type": "object",
                            "properties": {
                                "command": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "args": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "image": {"type": "string"},
                            },
                            "additionalProperties": False,
                        }
                    },
                    "additionalProperties": False,
                    "required": ["kind", "ptype", "deploy"],
                },
            },
        },
    },
    "required": ["pipeline"],
    "additionalProperties": False,
}
