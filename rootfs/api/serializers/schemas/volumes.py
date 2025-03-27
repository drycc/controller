SCHEMA = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "nfs": {
            "type": "object",
            "properties": {
                "server": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["server", "path"],
        },
        "oss": {
            "type": "object",
            "properties": {
                "bucket": {"type": "string"},
                "server": {"type": "string"},
                "access_key": {"type": "string"},
                "secret_key": {"type": "string"},
            },
            "required": ["bucket", "server", "access_key", "secret_key"],
        },
    },
}
