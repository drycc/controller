HTTP_HEADER_FILTER_SCHEMA = {
    "set": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "value": {"type": "string"}
            }
        }
    },
    "add": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "value": {"type": "string"}
            }
        }
    },
    "remove": {"type": "array"}
}

FILTER_SCHEMA = {
    # Type identifies the type of filter to apply.
    # As with other API fields, types are classified into three conformance levels:
    "type": {
        "type": "string",
        "enum": ["ExtensionRef", "RequestHeaderModifier", "RequestMirror", "RequestRedirect", "ResponseHeaderModifier", "URLRewrite"],  # noqa
    },
    # ExtensionRef is an optional, implementation-specific extension to the “filter” behavior. # noqa
    # For example, resource “myroutefilter” in group “networking.example.net”).
    # ExtensionRef MUST NOT be used for core and extended filters.
    "extensionRef": {
        "type": "object",
        "properties": {
            "group": {"type": "string"},
            "kind": {"type": "string"},
            "name": {"type": "string"}
        },
        "required": ["group", "kind", "name"],
        "additionalProperties": False
    },
    # RequestHeaderModifier defines a schema for a filter that modifies request headers.
    "requestHeaderModifier": {
        "type": "object",
        "properties": HTTP_HEADER_FILTER_SCHEMA,
        "additionalProperties": False
    },
    # ResponseHeaderModifier defines a schema for a filter that modifies response headers.
    "responseHeaderModifier": {
        "type": "object",
        "properties": HTTP_HEADER_FILTER_SCHEMA,
        "additionalProperties": False
    },
    # RequestMirror defines a schema for a filter that mirrors requests.
    # Requests are sent to the specified destination, but responses from that destination are ignored. # noqa
    "requestMirror": {
        "type": "object",
        "properties": {
            "backendRef": {
                "properties": {
                    "group": {"type": "string"},
                    "kind": {"type": "string"},
                    "name": {"type": "string"},
                    "namespace": {"type": "string"},
                    "port": {"type": "integer"},
                },
                "required": ["name"],
                "additionalProperties": False
            },
        },
        "required": ["backendRef"],
        "additionalProperties": False
    },
    # RequestRedirect defines a schema for a filter that responds to the request with an HTTP redirection. # noqa
    "requestRedirect": {
        "type": "object",
        "properties": {
            "scheme": {"type": "string"},
            "hostname": {"type": "string"},
            "path": {"type": "string"},
            "port": {"type": "integer"},
            "statusCode": {"type": "integer"}
        }
    },
    # URLRewrite defines a schema for a filter that modifies a request during forwarding
    "urlRewrite": {
        "hostname": {"type": "string"},
        "path": {"type": "string"},
    }
}

RULES_SCHEMA = {
    "type": "array",
    "items": {
        "properties": {
            # Matches define conditions used for matching the rule against incoming HTTP requests. # noqa
            # Each match is independent, i.e. this rule will be matched if any one of the matches is satisfied. # noqa
            # More info: https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/v1beta1.HTTPRouteMatch # noqa
            "matches": {
                "type": "array",
                "items": {
                    "properties": {
                        # Path specifies a HTTP request path matcher.
                        # If this field is not specified, a default prefix match on the “/” path is provided. # noqa
                        "path": {
                            "type": "object",
                            "properties": {
                                "type": {
                                    "type": "string",
                                    "enum": ["Exact", "PathPrefix", "RegularExpression"],
                                    "default": "PathPrefix"
                                },
                                "value": {"type": "string"}
                            },
                            "additionalProperties": False
                        },
                        # Headers specifies HTTP request header matchers. Multiple match values are ANDed together, # noqa
                        # meaning, a request must match all the specified headers to select the route. # noqa
                        # gateway.networking.k8s.io/v1beta1.HTTPHeaderMatch
                        # More info: https: // gateway-api.sigs.k8s.io/references/spec /
                        "headers": {
                            "type": "array",
                            "items": {
                                "properties": {
                                    "type": {
                                        "type": "string",
                                        "enum": ["Exact", "RegularExpression"],
                                        "default": "Exact"
                                    },
                                    "name": {"type": "string"},
                                    "value": {"type": "string"}
                                },
                                "additionalProperties": False
                            }
                        },
                        # QueryParams specifies HTTP query parameter matchers. Multiple match values are ANDed together, # noqa
                        # meaning, a request must match all the specified query parameters to select the route. # noqa
                        "queryParams": {
                            "type": "array",
                            "items": {
                                "properties": {
                                    "type": {
                                        "type": "string",
                                        "enum": ["Exact", "RegularExpression"],
                                        "default": "Exact"
                                    },
                                    "name": {"type": "string"},
                                    "value": {"type": "string"}
                                },
                                "additionalProperties": False
                            }
                        },
                        "method": {
                            "type": "string",
                            "enum": ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"],  # noqa
                        }
                    },
                    "additionalProperties": False
                }
            },
            # Filters define the filters that are applied to requests that match this rule.
            # More info: https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/v1beta1.HTTPRouteFilter # noqa
            "filters": {
                "type": "array",
                "items": {
                    "properties": FILTER_SCHEMA,
                    "additionalProperties": False
                },
            },
            # BackendRefs defines the backend(s) where matching requests should be sent.
            # More info: https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/v1beta1.HTTPBackendRef # noqa
            "backendRefs": {
                "type": "array",
                "items": {
                    "properties": {
                        "filters": {
                            "type": "array",
                            "items": {
                                "properties": FILTER_SCHEMA,
                                "additionalProperties": False
                            },
                        },
                        "group": {"type": "string"},
                        "kind": {"type": "string"},
                        "name": {"type": "string"},
                        "namespace": {"type": "string"},
                        "port": {"type": "integer"},
                        "weight": {"type": "integer"}
                    },
                    "required": ["name"],
                    "additionalProperties": False
                }
            },
            "timeouts": {
                "request": {"type": "string"},
                "backendRequest": {"type": "string"}
            }
        },
        "required": ["backendRefs"],
        "additionalProperties": False
    }
}

SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "properties": {
        "canary": RULES_SCHEMA,
        "stable": RULES_SCHEMA,
    },
    "required": ["canary", "stable"],
    "additionalProperties": False
}
