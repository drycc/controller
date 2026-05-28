PARENT_REF_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["name", "port"],
    "properties": {
        "name": {
            "type": "string",
        },
        "port": {
            "type": "integer",
            "minimum": 1,
            "maximum": 65535,
        },
    },
}


PARENT_REFS_SCHEMA = {
    "$schema": "http://json-schema.org/schema#",
    "type": "array",
    "items": PARENT_REF_SCHEMA,
}
