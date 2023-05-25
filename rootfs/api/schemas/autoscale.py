SCHEMA = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        # minimum replicas autoscale will keep resource at based on load
        "min": {"type": "integer"},
        # maximum replicas autoscale will keep resource at based on load
        "max": {"type": "integer"},
        # how much CPU load there is to trigger scaling rules
        "cpu_percent": {"type": "integer"},
    },
    "required": ["min", "max", "cpu_percent"],
}
