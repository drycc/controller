SCHEMA = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "nfs": {
            "type": "object",
            "properties": {
                "server": {"type": "string"},
                "path": {"type": "string"},
                "readOnly": {"type": "boolean"},
            },
            "required": ["server", "path", "readOnly"],
        },
    },
}
