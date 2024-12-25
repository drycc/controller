PROCTYPE_REGEX = r'^(?P<type>[a-z0-9]+(\-[a-z0-9]+)*)$'
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
                "config": {
                    "oneOf": [
                        {
                            "type": "object",
                            "patternProperties": {
                                PROCTYPE_REGEX: {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "value": {"type": "string"},
                                        },
                                        "additionalProperties": False,
                                    },
                                },
                            },
                            "minProperties": 1,
                            "additionalProperties": False,
                        },
                        {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "value": {"type": "string"},
                                },
                                "additionalProperties": False,
                            },
                        },
                    ]
                }
            },
        },
        "config": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "group": {"type": "string"},
                    "value": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        "run": {
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
                        }
                    }
                },
            },
            "additionalProperties": False,
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
                        "config": {
                            "env": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "value": {"type": "string"},
                                    },
                                    "additionalProperties": False,
                                },
                            },
                            "ref": {
                                "type": "array",
                                "items": {"type": "string"},
                            }
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
