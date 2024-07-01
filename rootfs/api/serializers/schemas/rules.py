# flake8: noqa


TCP_RULES_SCHEMA = {
    "description": "Rules are a list of TCP matchers and actions.",
    "items": {
        "description": "TCPRouteRule is the configuration for a given rule.",
        "properties": {
            "backendRefs": {
                "description": "BackendRefs defines the backend(s) where matching requests should be\nsent. If unspecified or invalid (refers to a non-existent resource or a\nService with no endpoints), the underlying implementation MUST actively\nreject connection attempts to this backend. Connection rejections must\nrespect weight; if an invalid backend is requested to have 80% of\nconnections, then 80% of connections must be rejected instead.\n\n\nSupport: Core for Kubernetes Service\n\n\nSupport: Extended for Kubernetes ServiceImport\n\n\nSupport: Implementation-specific for any other resource\n\n\nSupport for weight: Extended",
                "items": {
                    "description": "BackendRef defines how a Route should forward a request to a Kubernetes\nresource.\n\n\nNote that when a namespace different than the local namespace is specified, a\nReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\n<gateway:experimental:description>\n\n\nWhen the BackendRef points to a Kubernetes Service, implementations SHOULD\nhonor the appProtocol field if it is set for the target Service Port.\n\n\nImplementations supporting appProtocol SHOULD recognize the Kubernetes\nStandard Application Protocols defined in KEP-3726.\n\n\nIf a Service appProtocol isn't specified, an implementation MAY infer the\nbackend protocol through its own means. Implementations MAY infer the\nprotocol from the Route type referring to the backend Service.\n\n\nIf a Route is not able to send traffic to the backend using the specified\nprotocol then the backend is considered invalid. Implementations MUST set the\n\"ResolvedRefs\" condition to \"False\" with the \"UnsupportedProtocol\" reason.\n\n\n</gateway:experimental:description>\n\n\nNote that when the BackendTLSPolicy object is enabled by the implementation,\nthere are some extra rules about validity to consider here. See the fields\nwhere this struct is used for more information about the exact behavior.",
                    "properties": {
                        "group": {
                            "default": "",
                            "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                            "maxLength": 253,
                            "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                            "type": "string"
                        },
                        "kind": {
                            "default": "Service",
                            "description": "Kind is the Kubernetes resource kind of the referent. For example\n\"Service\".\n\n\nDefaults to \"Service\" when not specified.\n\n\nExternalName services can refer to CNAME DNS records that may live\noutside of the cluster and as such are difficult to reason about in\nterms of conformance. They also may not be safe to forward to (see\nCVE-2021-25740 for more information). Implementations SHOULD NOT\nsupport ExternalName Services.\n\n\nSupport: Core (Services with a type other than ExternalName)\n\n\nSupport: Implementation-specific (Services with type ExternalName)",
                            "maxLength": 63,
                            "minLength": 1,
                            "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                            "type": "string"
                        },
                        "name": {
                            "description": "Name is the name of the referent.",
                            "maxLength": 253,
                            "minLength": 1,
                            "type": "string"
                        },
                        "namespace": {
                            "description": "Namespace is the namespace of the backend. When unspecified, the local\nnamespace is inferred.\n\n\nNote that when a namespace different than the local namespace is specified,\na ReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\nSupport: Core",
                            "maxLength": 63,
                            "minLength": 1,
                            "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
                            "type": "string"
                        },
                        "port": {
                            "description": "Port specifies the destination port number to use for this resource.\nPort is required when the referent is a Kubernetes Service. In this\ncase, the port number is the service port number, not the target port.\nFor other resources, destination port might be derived from the referent\nresource or this field.",
                            "format": "int32",
                            "maximum": 65535,
                            "minimum": 1,
                            "type": "integer"
                        },
                        "weight": {
                            "default": 1,
                            "description": "Weight specifies the proportion of requests forwarded to the referenced\nbackend. This is computed as weight/(sum of all weights in this\nBackendRefs list). For non-zero values, there may be some epsilon from\nthe exact proportion defined here depending on the precision an\nimplementation supports. Weight is not a percentage and the sum of\nweights does not need to equal 100.\n\n\nIf only one backend is specified and it has a weight greater than 0, 100%\nof the traffic is forwarded to that backend. If weight is set to 0, no\ntraffic should be forwarded for this entry. If unspecified, weight\ndefaults to 1.\n\n\nSupport for this field varies based on the context where used.",
                            "format": "int32",
                            "maximum": 1000000,
                            "minimum": 0,
                            "type": "integer"
                        }
                    },
                    "required": [
                        "name"
                    ],
                    "type": "object",
                    "x-kubernetes-validations": [
                        {
                            "message": "Must have port for Service reference",
                            "rule": "(size(self.group) == 0 && self.kind == 'Service') ? has(self.port) : true"
                        }
                    ]
                },
                "maxItems": 16,
                "minItems": 1,
                "type": "array"
            }
        },
        "type": "object"
    },
    "maxItems": 16,
    "minItems": 1,
    "type": "array"
}

UDP_RULES_SCHEMA = {
    "description": "Rules are a list of UDP matchers and actions.",
    "items": {
        "description": "UDPRouteRule is the configuration for a given rule.",
        "properties": {
            "backendRefs": {
                "description": "BackendRefs defines the backend(s) where matching requests should be\nsent. If unspecified or invalid (refers to a non-existent resource or a\nService with no endpoints), the underlying implementation MUST actively\nreject connection attempts to this backend. Packet drops must\nrespect weight; if an invalid backend is requested to have 80% of\nthe packets, then 80% of packets must be dropped instead.\n\n\nSupport: Core for Kubernetes Service\n\n\nSupport: Extended for Kubernetes ServiceImport\n\n\nSupport: Implementation-specific for any other resource\n\n\nSupport for weight: Extended",
                "items": {
                    "description": "BackendRef defines how a Route should forward a request to a Kubernetes\nresource.\n\n\nNote that when a namespace different than the local namespace is specified, a\nReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\n<gateway:experimental:description>\n\n\nWhen the BackendRef points to a Kubernetes Service, implementations SHOULD\nhonor the appProtocol field if it is set for the target Service Port.\n\n\nImplementations supporting appProtocol SHOULD recognize the Kubernetes\nStandard Application Protocols defined in KEP-3726.\n\n\nIf a Service appProtocol isn't specified, an implementation MAY infer the\nbackend protocol through its own means. Implementations MAY infer the\nprotocol from the Route type referring to the backend Service.\n\n\nIf a Route is not able to send traffic to the backend using the specified\nprotocol then the backend is considered invalid. Implementations MUST set the\n\"ResolvedRefs\" condition to \"False\" with the \"UnsupportedProtocol\" reason.\n\n\n</gateway:experimental:description>\n\n\nNote that when the BackendTLSPolicy object is enabled by the implementation,\nthere are some extra rules about validity to consider here. See the fields\nwhere this struct is used for more information about the exact behavior.",
                    "properties": {
                        "group": {
                            "default": "",
                            "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                            "maxLength": 253,
                            "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                            "type": "string"
                        },
                        "kind": {
                            "default": "Service",
                            "description": "Kind is the Kubernetes resource kind of the referent. For example\n\"Service\".\n\n\nDefaults to \"Service\" when not specified.\n\n\nExternalName services can refer to CNAME DNS records that may live\noutside of the cluster and as such are difficult to reason about in\nterms of conformance. They also may not be safe to forward to (see\nCVE-2021-25740 for more information). Implementations SHOULD NOT\nsupport ExternalName Services.\n\n\nSupport: Core (Services with a type other than ExternalName)\n\n\nSupport: Implementation-specific (Services with type ExternalName)",
                            "maxLength": 63,
                            "minLength": 1,
                            "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                            "type": "string"
                        },
                        "name": {
                            "description": "Name is the name of the referent.",
                            "maxLength": 253,
                            "minLength": 1,
                            "type": "string"
                        },
                        "namespace": {
                            "description": "Namespace is the namespace of the backend. When unspecified, the local\nnamespace is inferred.\n\n\nNote that when a namespace different than the local namespace is specified,\na ReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\nSupport: Core",
                            "maxLength": 63,
                            "minLength": 1,
                            "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
                            "type": "string"
                        },
                        "port": {
                            "description": "Port specifies the destination port number to use for this resource.\nPort is required when the referent is a Kubernetes Service. In this\ncase, the port number is the service port number, not the target port.\nFor other resources, destination port might be derived from the referent\nresource or this field.",
                            "format": "int32",
                            "maximum": 65535,
                            "minimum": 1,
                            "type": "integer"
                        },
                        "weight": {
                            "default": 1,
                            "description": "Weight specifies the proportion of requests forwarded to the referenced\nbackend. This is computed as weight/(sum of all weights in this\nBackendRefs list). For non-zero values, there may be some epsilon from\nthe exact proportion defined here depending on the precision an\nimplementation supports. Weight is not a percentage and the sum of\nweights does not need to equal 100.\n\n\nIf only one backend is specified and it has a weight greater than 0, 100%\nof the traffic is forwarded to that backend. If weight is set to 0, no\ntraffic should be forwarded for this entry. If unspecified, weight\ndefaults to 1.\n\n\nSupport for this field varies based on the context where used.",
                            "format": "int32",
                            "maximum": 1000000,
                            "minimum": 0,
                            "type": "integer"
                        }
                    },
                    "required": [
                        "name"
                    ],
                    "type": "object",
                    "x-kubernetes-validations": [
                        {
                            "message": "Must have port for Service reference",
                            "rule": "(size(self.group) == 0 && self.kind == 'Service') ? has(self.port) : true"
                        }
                    ]
                },
                "maxItems": 16,
                "minItems": 1,
                "type": "array"
            }
        },
        "type": "object"
    },
    "maxItems": 16,
    "minItems": 1,
    "type": "array"
}

TLS_RULES_SCHEMA = {
    "description": "Rules are a list of TLS matchers and actions.",
    "items": {
        "description": "TLSRouteRule is the configuration for a given rule.",
        "properties": {
            "backendRefs": {
                "description": "BackendRefs defines the backend(s) where matching requests should be\nsent. If unspecified or invalid (refers to a non-existent resource or\na Service with no endpoints), the rule performs no forwarding; if no\nfilters are specified that would result in a response being sent, the\nunderlying implementation must actively reject request attempts to this\nbackend, by rejecting the connection or returning a 500 status code.\nRequest rejections must respect weight; if an invalid backend is\nrequested to have 80% of requests, then 80% of requests must be rejected\ninstead.\n\n\nSupport: Core for Kubernetes Service\n\n\nSupport: Extended for Kubernetes ServiceImport\n\n\nSupport: Implementation-specific for any other resource\n\n\nSupport for weight: Extended",
                "items": {
                    "description": "BackendRef defines how a Route should forward a request to a Kubernetes\nresource.\n\n\nNote that when a namespace different than the local namespace is specified, a\nReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\n<gateway:experimental:description>\n\n\nWhen the BackendRef points to a Kubernetes Service, implementations SHOULD\nhonor the appProtocol field if it is set for the target Service Port.\n\n\nImplementations supporting appProtocol SHOULD recognize the Kubernetes\nStandard Application Protocols defined in KEP-3726.\n\n\nIf a Service appProtocol isn't specified, an implementation MAY infer the\nbackend protocol through its own means. Implementations MAY infer the\nprotocol from the Route type referring to the backend Service.\n\n\nIf a Route is not able to send traffic to the backend using the specified\nprotocol then the backend is considered invalid. Implementations MUST set the\n\"ResolvedRefs\" condition to \"False\" with the \"UnsupportedProtocol\" reason.\n\n\n</gateway:experimental:description>\n\n\nNote that when the BackendTLSPolicy object is enabled by the implementation,\nthere are some extra rules about validity to consider here. See the fields\nwhere this struct is used for more information about the exact behavior.",
                    "properties": {
                        "group": {
                            "default": "",
                            "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                            "maxLength": 253,
                            "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                            "type": "string"
                        },
                        "kind": {
                            "default": "Service",
                            "description": "Kind is the Kubernetes resource kind of the referent. For example\n\"Service\".\n\n\nDefaults to \"Service\" when not specified.\n\n\nExternalName services can refer to CNAME DNS records that may live\noutside of the cluster and as such are difficult to reason about in\nterms of conformance. They also may not be safe to forward to (see\nCVE-2021-25740 for more information). Implementations SHOULD NOT\nsupport ExternalName Services.\n\n\nSupport: Core (Services with a type other than ExternalName)\n\n\nSupport: Implementation-specific (Services with type ExternalName)",
                            "maxLength": 63,
                            "minLength": 1,
                            "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                            "type": "string"
                        },
                        "name": {
                            "description": "Name is the name of the referent.",
                            "maxLength": 253,
                            "minLength": 1,
                            "type": "string"
                        },
                        "namespace": {
                            "description": "Namespace is the namespace of the backend. When unspecified, the local\nnamespace is inferred.\n\n\nNote that when a namespace different than the local namespace is specified,\na ReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\nSupport: Core",
                            "maxLength": 63,
                            "minLength": 1,
                            "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
                            "type": "string"
                        },
                        "port": {
                            "description": "Port specifies the destination port number to use for this resource.\nPort is required when the referent is a Kubernetes Service. In this\ncase, the port number is the service port number, not the target port.\nFor other resources, destination port might be derived from the referent\nresource or this field.",
                            "format": "int32",
                            "maximum": 65535,
                            "minimum": 1,
                            "type": "integer"
                        },
                        "weight": {
                            "default": 1,
                            "description": "Weight specifies the proportion of requests forwarded to the referenced\nbackend. This is computed as weight/(sum of all weights in this\nBackendRefs list). For non-zero values, there may be some epsilon from\nthe exact proportion defined here depending on the precision an\nimplementation supports. Weight is not a percentage and the sum of\nweights does not need to equal 100.\n\n\nIf only one backend is specified and it has a weight greater than 0, 100%\nof the traffic is forwarded to that backend. If weight is set to 0, no\ntraffic should be forwarded for this entry. If unspecified, weight\ndefaults to 1.\n\n\nSupport for this field varies based on the context where used.",
                            "format": "int32",
                            "maximum": 1000000,
                            "minimum": 0,
                            "type": "integer"
                        }
                    },
                    "required": [
                        "name"
                    ],
                    "type": "object",
                    "x-kubernetes-validations": [
                        {
                            "message": "Must have port for Service reference",
                            "rule": "(size(self.group) == 0 && self.kind == 'Service') ? has(self.port) : true"
                        }
                    ]
                },
                "maxItems": 16,
                "minItems": 1,
                "type": "array"
            }
        },
        "type": "object"
    },
    "maxItems": 16,
    "minItems": 1,
    "type": "array"
}

HTTP_RULES_SCHEMA = {
    "description": "Rules are a list of HTTP matchers, filters and actions.",
    "items": {
        "properties": {
            "backendRefs": {
                "items": {
                    "properties": {
                        "filters": {
                            "items": {
                                "properties": {
                                    "extensionRef": {
                                        "properties": {
                                            "group": {
                                                "description": "",
                                                "maxLength": 253,
                                                "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                                "type": "string"
                                            },
                                            "kind": {
                                                "description": "Kind is kind of the referent. For example \"HTTPRoute\" or \"Service\".",
                                                "maxLength": 63,
                                                "minLength": 1,
                                                "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                                                "type": "string"
                                            },
                                            "name": {
                                                "description": "Name is the name of the referent.",
                                                "maxLength": 253,
                                                "minLength": 1,
                                                "type": "string"
                                            }
                                        },
                                        "required": [
                                            "group",
                                            "kind",
                                            "name"
                                        ],
                                        "type": "object"
                                    },
                                    "requestHeaderModifier": {
                                        "description": "RequestHeaderModifier defines a schema for a filter that modifies request\nheaders.\n\n\nSupport: Core",
                                        "properties": {
                                            "add": {
                                                "description": "Add adds the given header(s) (name, value) to the request\nbefore the action. It appends to any existing values associated\nwith the header name.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  add:\n  - name: \"my-header\"\n    value: \"bar,baz\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: foo,bar,baz",
                                                "items": {
                                                    "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                                    "properties": {
                                                        "name": {
                                                            "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                            "maxLength": 256,
                                                            "minLength": 1,
                                                            "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                            "type": "string"
                                                        },
                                                        "value": {
                                                            "description": "Value is the value of HTTP Header to be matched.",
                                                            "maxLength": 4096,
                                                            "minLength": 1,
                                                            "type": "string"
                                                        }
                                                    },
                                                    "required": [
                                                        "name",
                                                        "value"
                                                    ],
                                                    "type": "object"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-map-keys": [
                                                    "name"
                                                ],
                                                "x-kubernetes-list-type": "map"
                                            },
                                            "remove": {
                                                "description": "Remove the given header(s) from the HTTP request before the action. The\nvalue of Remove is a list of HTTP header names. Note that the header\nnames are case-insensitive (see\nhttps://datatracker.ietf.org/doc/html/rfc2616#section-4.2).\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header1: foo\n  my-header2: bar\n  my-header3: baz\n\n\nConfig:\n  remove: [\"my-header1\", \"my-header3\"]\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header2: bar",
                                                "items": {
                                                    "type": "string"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-type": "set"
                                            },
                                            "set": {
                                                "description": "Set overwrites the request with the given header (name, value)\nbefore the action.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  set:\n  - name: \"my-header\"\n    value: \"bar\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: bar",
                                                "items": {
                                                    "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                                    "properties": {
                                                        "name": {
                                                            "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                            "maxLength": 256,
                                                            "minLength": 1,
                                                            "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                            "type": "string"
                                                        },
                                                        "value": {
                                                            "description": "Value is the value of HTTP Header to be matched.",
                                                            "maxLength": 4096,
                                                            "minLength": 1,
                                                            "type": "string"
                                                        }
                                                    },
                                                    "required": [
                                                        "name",
                                                        "value"
                                                    ],
                                                    "type": "object"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-map-keys": [
                                                    "name"
                                                ],
                                                "x-kubernetes-list-type": "map"
                                            }
                                        },
                                        "type": "object"
                                    },
                                    "requestMirror": {
                                        "description": "RequestMirror defines a schema for a filter that mirrors requests.\nRequests are sent to the specified destination, but responses from\nthat destination are ignored.\n\n\nThis filter can be used multiple times within the same rule. Note that\nnot all implementations will be able to support mirroring to multiple\nbackends.\n\n\nSupport: Extended",
                                        "properties": {
                                            "backendRef": {
                                                "description": "BackendRef references a resource where mirrored requests are sent.\n\n\nMirrored requests must be sent only to a single destination endpoint\nwithin this BackendRef, irrespective of how many endpoints are present\nwithin this BackendRef.\n\n\nIf the referent cannot be found, this BackendRef is invalid and must be\ndropped from the Gateway. The controller must ensure the \"ResolvedRefs\"\ncondition on the Route status is set to `status: False` and not configure\nthis backend in the underlying implementation.\n\n\nIf there is a cross-namespace reference to an *existing* object\nthat is not allowed by a ReferenceGrant, the controller must ensure the\n\"ResolvedRefs\"  condition on the Route is set to `status: False`,\nwith the \"RefNotPermitted\" reason and not configure this backend in the\nunderlying implementation.\n\n\nIn either error case, the Message of the `ResolvedRefs` Condition\nshould be used to provide more detail about the problem.\n\n\nSupport: Extended for Kubernetes Service\n\n\nSupport: Implementation-specific for any other resource",
                                                "properties": {
                                                    "group": {
                                                        "default": "",
                                                        "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                                                        "maxLength": 253,
                                                        "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                                        "type": "string"
                                                    },
                                                    "kind": {
                                                        "default": "Service",
                                                        "description": "Kind is the Kubernetes resource kind of the referent. For example\n\"Service\".\n\n\nDefaults to \"Service\" when not specified.\n\n\nExternalName services can refer to CNAME DNS records that may live\noutside of the cluster and as such are difficult to reason about in\nterms of conformance. They also may not be safe to forward to (see\nCVE-2021-25740 for more information). Implementations SHOULD NOT\nsupport ExternalName Services.\n\n\nSupport: Core (Services with a type other than ExternalName)\n\n\nSupport: Implementation-specific (Services with type ExternalName)",
                                                        "maxLength": 63,
                                                        "minLength": 1,
                                                        "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                                                        "type": "string"
                                                    },
                                                    "name": {
                                                        "description": "Name is the name of the referent.",
                                                        "maxLength": 253,
                                                        "minLength": 1,
                                                        "type": "string"
                                                    },
                                                    "namespace": {
                                                        "description": "Namespace is the namespace of the backend. When unspecified, the local\nnamespace is inferred.\n\n\nNote that when a namespace different than the local namespace is specified,\na ReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\nSupport: Core",
                                                        "maxLength": 63,
                                                        "minLength": 1,
                                                        "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
                                                        "type": "string"
                                                    },
                                                    "port": {
                                                        "description": "Port specifies the destination port number to use for this resource.\nPort is required when the referent is a Kubernetes Service. In this\ncase, the port number is the service port number, not the target port.\nFor other resources, destination port might be derived from the referent\nresource or this field.",
                                                        "format": "int32",
                                                        "maximum": 65535,
                                                        "minimum": 1,
                                                        "type": "integer"
                                                    }
                                                },
                                                "required": [
                                                    "name"
                                                ],
                                                "type": "object",
                                                "x-kubernetes-validations": [
                                                    {
                                                        "message": "Must have port for Service reference",
                                                        "rule": "(size(self.group) == 0 && self.kind == 'Service') ? has(self.port) : true"
                                                    }
                                                ]
                                            }
                                        },
                                        "required": [
                                            "backendRef"
                                        ],
                                        "type": "object"
                                    },
                                    "requestRedirect": {
                                        "description": "RequestRedirect defines a schema for a filter that responds to the\nrequest with an HTTP redirection.\n\n\nSupport: Core",
                                        "properties": {
                                            "hostname": {
                                                "description": "Hostname is the hostname to be used in the value of the `Location`\nheader in the response.\nWhen empty, the hostname in the `Host` header of the request is used.\n\n\nSupport: Core",
                                                "maxLength": 253,
                                                "minLength": 1,
                                                "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                                "type": "string"
                                            },
                                            "path": {
                                                "description": "Path defines parameters used to modify the path of the incoming request.\nThe modified path is then used to construct the `Location` header. When\nempty, the request path is used as-is.\n\n\nSupport: Extended",
                                                "properties": {
                                                    "replaceFullPath": {
                                                        "description": "ReplaceFullPath specifies the value with which to replace the full path\nof a request during a rewrite or redirect.",
                                                        "maxLength": 1024,
                                                        "type": "string"
                                                    },
                                                    "replacePrefixMatch": {
                                                        "description": "ReplacePrefixMatch specifies the value with which to replace the prefix\nmatch of a request during a rewrite or redirect. For example, a request\nto \"/foo/bar\" with a prefix match of \"/foo\" and a ReplacePrefixMatch\nof \"/xyz\" would be modified to \"/xyz/bar\".\n\n\nNote that this matches the behavior of the PathPrefix match type. This\nmatches full path elements. A path element refers to the list of labels\nin the path split by the `/` separator. When specified, a trailing `/` is\nignored. For example, the paths `/abc`, `/abc/`, and `/abc/def` would all\nmatch the prefix `/abc`, but the path `/abcd` would not.\n\n\nReplacePrefixMatch is only compatible with a `PathPrefix` HTTPRouteMatch.\nUsing any other HTTPRouteMatch type on the same HTTPRouteRule will result in\nthe implementation setting the Accepted Condition for the Route to `status: False`.\n\n\nRequest Path | Prefix Match | Replace Prefix | Modified Path\n-------------|--------------|----------------|----------\n/foo/bar     | /foo         | /xyz           | /xyz/bar\n/foo/bar     | /foo         | /xyz/          | /xyz/bar\n/foo/bar     | /foo/        | /xyz           | /xyz/bar\n/foo/bar     | /foo/        | /xyz/          | /xyz/bar\n/foo         | /foo         | /xyz           | /xyz\n/foo/        | /foo         | /xyz           | /xyz/\n/foo/bar     | /foo         | <empty string> | /bar\n/foo/        | /foo         | <empty string> | /\n/foo         | /foo         | <empty string> | /\n/foo/        | /foo         | /              | /\n/foo         | /foo         | /              | /",
                                                        "maxLength": 1024,
                                                        "type": "string"
                                                    },
                                                    "type": {
                                                        "description": "Type defines the type of path modifier. Additional types may be\nadded in a future release of the API.\n\n\nNote that values may be added to this enum, implementations\nmust ensure that unknown values will not cause a crash.\n\n\nUnknown values here must result in the implementation setting the\nAccepted Condition for the Route to `status: False`, with a\nReason of `UnsupportedValue`.",
                                                        "enum": [
                                                            "ReplaceFullPath",
                                                            "ReplacePrefixMatch"
                                                        ],
                                                        "type": "string"
                                                    }
                                                },
                                                "required": [
                                                    "type"
                                                ],
                                                "type": "object",
                                                "x-kubernetes-validations": [
                                                    {
                                                        "message": "replaceFullPath must be specified when type is set to 'ReplaceFullPath'",
                                                        "rule": "self.type == 'ReplaceFullPath' ? has(self.replaceFullPath) : true"
                                                    },
                                                    {
                                                        "message": "type must be 'ReplaceFullPath' when replaceFullPath is set",
                                                        "rule": "has(self.replaceFullPath) ? self.type == 'ReplaceFullPath' : true"
                                                    },
                                                    {
                                                        "message": "replacePrefixMatch must be specified when type is set to 'ReplacePrefixMatch'",
                                                        "rule": "self.type == 'ReplacePrefixMatch' ? has(self.replacePrefixMatch) : true"
                                                    },
                                                    {
                                                        "message": "type must be 'ReplacePrefixMatch' when replacePrefixMatch is set",
                                                        "rule": "has(self.replacePrefixMatch) ? self.type == 'ReplacePrefixMatch' : true"
                                                    }
                                                ]
                                            },
                                            "port": {
                                                "description": "Port is the port to be used in the value of the `Location`\nheader in the response.\n\n\nIf no port is specified, the redirect port MUST be derived using the\nfollowing rules:\n\n\n* If redirect scheme is not-empty, the redirect port MUST be the well-known\n  port associated with the redirect scheme. Specifically \"http\" to port 80\n  and \"https\" to port 443. If the redirect scheme does not have a\n  well-known port, the listener port of the Gateway SHOULD be used.\n* If redirect scheme is empty, the redirect port MUST be the Gateway\n  Listener port.\n\n\nImplementations SHOULD NOT add the port number in the 'Location'\nheader in the following cases:\n\n\n* A Location header that will use HTTP (whether that is determined via\n  the Listener protocol or the Scheme field) _and_ use port 80.\n* A Location header that will use HTTPS (whether that is determined via\n  the Listener protocol or the Scheme field) _and_ use port 443.\n\n\nSupport: Extended",
                                                "format": "int32",
                                                "maximum": 65535,
                                                "minimum": 1,
                                                "type": "integer"
                                            },
                                            "scheme": {
                                                "description": "Scheme is the scheme to be used in the value of the `Location` header in\nthe response. When empty, the scheme of the request is used.\n\n\nScheme redirects can affect the port of the redirect, for more information,\nrefer to the documentation for the port field of this filter.\n\n\nNote that values may be added to this enum, implementations\nmust ensure that unknown values will not cause a crash.\n\n\nUnknown values here must result in the implementation setting the\nAccepted Condition for the Route to `status: False`, with a\nReason of `UnsupportedValue`.\n\n\nSupport: Extended",
                                                "enum": [
                                                    "http",
                                                    "https"
                                                ],
                                                "type": "string"
                                            },
                                            "statusCode": {
                                                "default": 302,
                                                "description": "StatusCode is the HTTP status code to be used in response.\n\n\nNote that values may be added to this enum, implementations\nmust ensure that unknown values will not cause a crash.\n\n\nUnknown values here must result in the implementation setting the\nAccepted Condition for the Route to `status: False`, with a\nReason of `UnsupportedValue`.\n\n\nSupport: Core",
                                                "enum": [
                                                    301,
                                                    302
                                                ],
                                                "type": "integer"
                                            }
                                        },
                                        "type": "object"
                                    },
                                    "responseHeaderModifier": {
                                        "description": "ResponseHeaderModifier defines a schema for a filter that modifies response\nheaders.\n\n\nSupport: Extended",
                                        "properties": {
                                            "add": {
                                                "description": "Add adds the given header(s) (name, value) to the request\nbefore the action. It appends to any existing values associated\nwith the header name.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  add:\n  - name: \"my-header\"\n    value: \"bar,baz\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: foo,bar,baz",
                                                "items": {
                                                    "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                                    "properties": {
                                                        "name": {
                                                            "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                            "maxLength": 256,
                                                            "minLength": 1,
                                                            "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                            "type": "string"
                                                        },
                                                        "value": {
                                                            "description": "Value is the value of HTTP Header to be matched.",
                                                            "maxLength": 4096,
                                                            "minLength": 1,
                                                            "type": "string"
                                                        }
                                                    },
                                                    "required": [
                                                        "name",
                                                        "value"
                                                    ],
                                                    "type": "object"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-map-keys": [
                                                    "name"
                                                ],
                                                "x-kubernetes-list-type": "map"
                                            },
                                            "remove": {
                                                "description": "Remove the given header(s) from the HTTP request before the action. The\nvalue of Remove is a list of HTTP header names. Note that the header\nnames are case-insensitive (see\nhttps://datatracker.ietf.org/doc/html/rfc2616#section-4.2).\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header1: foo\n  my-header2: bar\n  my-header3: baz\n\n\nConfig:\n  remove: [\"my-header1\", \"my-header3\"]\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header2: bar",
                                                "items": {
                                                    "type": "string"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-type": "set"
                                            },
                                            "set": {
                                                "description": "Set overwrites the request with the given header (name, value)\nbefore the action.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  set:\n  - name: \"my-header\"\n    value: \"bar\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: bar",
                                                "items": {
                                                    "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                                    "properties": {
                                                        "name": {
                                                            "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                            "maxLength": 256,
                                                            "minLength": 1,
                                                            "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                            "type": "string"
                                                        },
                                                        "value": {
                                                            "description": "Value is the value of HTTP Header to be matched.",
                                                            "maxLength": 4096,
                                                            "minLength": 1,
                                                            "type": "string"
                                                        }
                                                    },
                                                    "required": [
                                                        "name",
                                                        "value"
                                                    ],
                                                    "type": "object"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-map-keys": [
                                                    "name"
                                                ],
                                                "x-kubernetes-list-type": "map"
                                            }
                                        },
                                        "type": "object"
                                    },
                                    "type": {
                                        "description": "Type identifies the type of filter to apply. As with other API fields,\ntypes are classified into three conformance levels:\n\n\n- Core: Filter types and their corresponding configuration defined by\n  \"Support: Core\" in this package, e.g. \"RequestHeaderModifier\". All\n  implementations must support core filters.\n\n\n- Extended: Filter types and their corresponding configuration defined by\n  \"Support: Extended\" in this package, e.g. \"RequestMirror\". Implementers\n  are encouraged to support extended filters.\n\n\n- Implementation-specific: Filters that are defined and supported by\n  specific vendors.\n  In the future, filters showing convergence in behavior across multiple\n  implementations will be considered for inclusion in extended or core\n  conformance levels. Filter-specific configuration for such filters\n  is specified using the ExtensionRef field. `Type` should be set to\n  \"ExtensionRef\" for custom filters.\n\n\nImplementers are encouraged to define custom implementation types to\nextend the core API with implementation-specific behavior.\n\n\nIf a reference to a custom filter type cannot be resolved, the filter\nMUST NOT be skipped. Instead, requests that would have been processed by\nthat filter MUST receive a HTTP error response.\n\n\nNote that values may be added to this enum, implementations\nmust ensure that unknown values will not cause a crash.\n\n\nUnknown values here must result in the implementation setting the\nAccepted Condition for the Route to `status: False`, with a\nReason of `UnsupportedValue`.",
                                        "enum": [
                                            "RequestHeaderModifier",
                                            "ResponseHeaderModifier",
                                            "RequestMirror",
                                            "RequestRedirect",
                                            "URLRewrite",
                                            "ExtensionRef"
                                        ],
                                        "type": "string"
                                    },
                                    "urlRewrite": {
                                        "description": "URLRewrite defines a schema for a filter that modifies a request during forwarding.\n\n\nSupport: Extended",
                                        "properties": {
                                            "hostname": {
                                                "description": "Hostname is the value to be used to replace the Host header value during\nforwarding.\n\n\nSupport: Extended",
                                                "maxLength": 253,
                                                "minLength": 1,
                                                "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                                "type": "string"
                                            },
                                            "path": {
                                                "description": "Path defines a path rewrite.\n\n\nSupport: Extended",
                                                "properties": {
                                                    "replaceFullPath": {
                                                        "description": "ReplaceFullPath specifies the value with which to replace the full path\nof a request during a rewrite or redirect.",
                                                        "maxLength": 1024,
                                                        "type": "string"
                                                    },
                                                    "replacePrefixMatch": {
                                                        "description": "ReplacePrefixMatch specifies the value with which to replace the prefix\nmatch of a request during a rewrite or redirect. For example, a request\nto \"/foo/bar\" with a prefix match of \"/foo\" and a ReplacePrefixMatch\nof \"/xyz\" would be modified to \"/xyz/bar\".\n\n\nNote that this matches the behavior of the PathPrefix match type. This\nmatches full path elements. A path element refers to the list of labels\nin the path split by the `/` separator. When specified, a trailing `/` is\nignored. For example, the paths `/abc`, `/abc/`, and `/abc/def` would all\nmatch the prefix `/abc`, but the path `/abcd` would not.\n\n\nReplacePrefixMatch is only compatible with a `PathPrefix` HTTPRouteMatch.\nUsing any other HTTPRouteMatch type on the same HTTPRouteRule will result in\nthe implementation setting the Accepted Condition for the Route to `status: False`.\n\n\nRequest Path | Prefix Match | Replace Prefix | Modified Path\n-------------|--------------|----------------|----------\n/foo/bar     | /foo         | /xyz           | /xyz/bar\n/foo/bar     | /foo         | /xyz/          | /xyz/bar\n/foo/bar     | /foo/        | /xyz           | /xyz/bar\n/foo/bar     | /foo/        | /xyz/          | /xyz/bar\n/foo         | /foo         | /xyz           | /xyz\n/foo/        | /foo         | /xyz           | /xyz/\n/foo/bar     | /foo         | <empty string> | /bar\n/foo/        | /foo         | <empty string> | /\n/foo         | /foo         | <empty string> | /\n/foo/        | /foo         | /              | /\n/foo         | /foo         | /              | /",
                                                        "maxLength": 1024,
                                                        "type": "string"
                                                    },
                                                    "type": {
                                                        "description": "Type defines the type of path modifier. Additional types may be\nadded in a future release of the API.\n\n\nNote that values may be added to this enum, implementations\nmust ensure that unknown values will not cause a crash.\n\n\nUnknown values here must result in the implementation setting the\nAccepted Condition for the Route to `status: False`, with a\nReason of `UnsupportedValue`.",
                                                        "enum": [
                                                            "ReplaceFullPath",
                                                            "ReplacePrefixMatch"
                                                        ],
                                                        "type": "string"
                                                    }
                                                },
                                                "required": [
                                                    "type"
                                                ],
                                                "type": "object",
                                                "x-kubernetes-validations": [
                                                    {
                                                        "message": "replaceFullPath must be specified when type is set to 'ReplaceFullPath'",
                                                        "rule": "self.type == 'ReplaceFullPath' ? has(self.replaceFullPath) : true"
                                                    },
                                                    {
                                                        "message": "type must be 'ReplaceFullPath' when replaceFullPath is set",
                                                        "rule": "has(self.replaceFullPath) ? self.type == 'ReplaceFullPath' : true"
                                                    },
                                                    {
                                                        "message": "replacePrefixMatch must be specified when type is set to 'ReplacePrefixMatch'",
                                                        "rule": "self.type == 'ReplacePrefixMatch' ? has(self.replacePrefixMatch) : true"
                                                    },
                                                    {
                                                        "message": "type must be 'ReplacePrefixMatch' when replacePrefixMatch is set",
                                                        "rule": "has(self.replacePrefixMatch) ? self.type == 'ReplacePrefixMatch' : true"
                                                    }
                                                ]
                                            }
                                        },
                                        "type": "object"
                                    }
                                },
                                "required": [
                                    "type"
                                ],
                                "type": "object",
                                "x-kubernetes-validations": [
                                    {
                                        "message": "filter.requestHeaderModifier must be nil if the filter.type is not RequestHeaderModifier",
                                        "rule": "!(has(self.requestHeaderModifier) && self.type != 'RequestHeaderModifier')"
                                    },
                                    {
                                        "message": "filter.requestHeaderModifier must be specified for RequestHeaderModifier filter.type",
                                        "rule": "!(!has(self.requestHeaderModifier) && self.type == 'RequestHeaderModifier')"
                                    },
                                    {
                                        "message": "filter.responseHeaderModifier must be nil if the filter.type is not ResponseHeaderModifier",
                                        "rule": "!(has(self.responseHeaderModifier) && self.type != 'ResponseHeaderModifier')"
                                    },
                                    {
                                        "message": "filter.responseHeaderModifier must be specified for ResponseHeaderModifier filter.type",
                                        "rule": "!(!has(self.responseHeaderModifier) && self.type == 'ResponseHeaderModifier')"
                                    },
                                    {
                                        "message": "filter.requestMirror must be nil if the filter.type is not RequestMirror",
                                        "rule": "!(has(self.requestMirror) && self.type != 'RequestMirror')"
                                    },
                                    {
                                        "message": "filter.requestMirror must be specified for RequestMirror filter.type",
                                        "rule": "!(!has(self.requestMirror) && self.type == 'RequestMirror')"
                                    },
                                    {
                                        "message": "filter.requestRedirect must be nil if the filter.type is not RequestRedirect",
                                        "rule": "!(has(self.requestRedirect) && self.type != 'RequestRedirect')"
                                    },
                                    {
                                        "message": "filter.requestRedirect must be specified for RequestRedirect filter.type",
                                        "rule": "!(!has(self.requestRedirect) && self.type == 'RequestRedirect')"
                                    },
                                    {
                                        "message": "filter.urlRewrite must be nil if the filter.type is not URLRewrite",
                                        "rule": "!(has(self.urlRewrite) && self.type != 'URLRewrite')"
                                    },
                                    {
                                        "message": "filter.urlRewrite must be specified for URLRewrite filter.type",
                                        "rule": "!(!has(self.urlRewrite) && self.type == 'URLRewrite')"
                                    },
                                    {
                                        "message": "filter.extensionRef must be nil if the filter.type is not ExtensionRef",
                                        "rule": "!(has(self.extensionRef) && self.type != 'ExtensionRef')"
                                    },
                                    {
                                        "message": "filter.extensionRef must be specified for ExtensionRef filter.type",
                                        "rule": "!(!has(self.extensionRef) && self.type == 'ExtensionRef')"
                                    }
                                ]
                            },
                            "maxItems": 16,
                            "type": "array",
                            "x-kubernetes-validations": [
                                {
                                    "message": "May specify either httpRouteFilterRequestRedirect or httpRouteFilterRequestRewrite, but not both",
                                    "rule": "!(self.exists(f, f.type == 'RequestRedirect') && self.exists(f, f.type == 'URLRewrite'))"
                                },
                                {
                                    "message": "May specify either httpRouteFilterRequestRedirect or httpRouteFilterRequestRewrite, but not both",
                                    "rule": "!(self.exists(f, f.type == 'RequestRedirect') && self.exists(f, f.type == 'URLRewrite'))"
                                },
                                {
                                    "message": "RequestHeaderModifier filter cannot be repeated",
                                    "rule": "self.filter(f, f.type == 'RequestHeaderModifier').size() <= 1"
                                },
                                {
                                    "message": "ResponseHeaderModifier filter cannot be repeated",
                                    "rule": "self.filter(f, f.type == 'ResponseHeaderModifier').size() <= 1"
                                },
                                {
                                    "message": "RequestRedirect filter cannot be repeated",
                                    "rule": "self.filter(f, f.type == 'RequestRedirect').size() <= 1"
                                },
                                {
                                    "message": "URLRewrite filter cannot be repeated",
                                    "rule": "self.filter(f, f.type == 'URLRewrite').size() <= 1"
                                }
                            ]
                        },
                        "group": {
                            "default": "",
                            "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                            "maxLength": 253,
                            "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                            "type": "string"
                        },
                        "kind": {
                            "default": "Service",
                            "description": "Kind is the Kubernetes resource kind of the referent. For example\n\"Service\".\n\n\nDefaults to \"Service\" when not specified.\n\n\nExternalName services can refer to CNAME DNS records that may live\noutside of the cluster and as such are difficult to reason about in\nterms of conformance. They also may not be safe to forward to (see\nCVE-2021-25740 for more information). Implementations SHOULD NOT\nsupport ExternalName Services.\n\n\nSupport: Core (Services with a type other than ExternalName)\n\n\nSupport: Implementation-specific (Services with type ExternalName)",
                            "maxLength": 63,
                            "minLength": 1,
                            "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                            "type": "string"
                        },
                        "name": {
                            "description": "Name is the name of the referent.",
                            "maxLength": 253,
                            "minLength": 1,
                            "type": "string"
                        },
                        "namespace": {
                            "description": "Namespace is the namespace of the backend. When unspecified, the local\nnamespace is inferred.\n\n\nNote that when a namespace different than the local namespace is specified,\na ReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\nSupport: Core",
                            "maxLength": 63,
                            "minLength": 1,
                            "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
                            "type": "string"
                        },
                        "port": {
                            "description": "Port specifies the destination port number to use for this resource.\nPort is required when the referent is a Kubernetes Service. In this\ncase, the port number is the service port number, not the target port.\nFor other resources, destination port might be derived from the referent\nresource or this field.",
                            "format": "int32",
                            "maximum": 65535,
                            "minimum": 1,
                            "type": "integer"
                        },
                        "weight": {
                            "default": 1,
                            "description": "Weight specifies the proportion of requests forwarded to the referenced\nbackend. This is computed as weight/(sum of all weights in this\nBackendRefs list). For non-zero values, there may be some epsilon from\nthe exact proportion defined here depending on the precision an\nimplementation supports. Weight is not a percentage and the sum of\nweights does not need to equal 100.\n\n\nIf only one backend is specified and it has a weight greater than 0, 100%\nof the traffic is forwarded to that backend. If weight is set to 0, no\ntraffic should be forwarded for this entry. If unspecified, weight\ndefaults to 1.\n\n\nSupport for this field varies based on the context where used.",
                            "format": "int32",
                            "maximum": 1000000,
                            "minimum": 0,
                            "type": "integer"
                        }
                    },
                    "required": [
                        "name"
                    ],
                    "type": "object",
                    "x-kubernetes-validations": [
                        {
                            "message": "Must have port for Service reference",
                            "rule": "(size(self.group) == 0 && self.kind == 'Service') ? has(self.port) : true"
                        }
                    ]
                },
                "maxItems": 16,
                "type": "array"
            },
            "filters": {
                "description": "Filters define the filters that are applied to requests that match\nthis rule.\n\n\nWherever possible, implementations SHOULD implement filters in the order\nthey are specified.\n\n\nImplementations MAY choose to implement this ordering strictly, rejecting\nany combination or order of filters that can not be supported. If implementations\nchoose a strict interpretation of filter ordering, they MUST clearly document\nthat behavior.\n\n\nTo reject an invalid combination or order of filters, implementations SHOULD\nconsider the Route Rules with this configuration invalid. If all Route Rules\nin a Route are invalid, the entire Route would be considered invalid. If only\na portion of Route Rules are invalid, implementations MUST set the\n\"PartiallyInvalid\" condition for the Route.\n\n\nConformance-levels at this level are defined based on the type of filter:\n\n\n- ALL core filters MUST be supported by all implementations.\n- Implementers are encouraged to support extended filters.\n- Implementation-specific custom filters have no API guarantees across\n  implementations.\n\n\nSpecifying the same filter multiple times is not supported unless explicitly\nindicated in the filter.\n\n\nAll filters are expected to be compatible with each other except for the\nURLRewrite and RequestRedirect filters, which may not be combined. If an\nimplementation can not support other combinations of filters, they must clearly\ndocument that limitation. In cases where incompatible or unsupported\nfilters are specified and cause the `Accepted` condition to be set to status\n`False`, implementations may use the `IncompatibleFilters` reason to specify\nthis configuration error.\n\n\nSupport: Core",
                "items": {
                    "description": "HTTPRouteFilter defines processing steps that must be completed during the\nrequest or response lifecycle. HTTPRouteFilters are meant as an extension\npoint to express processing that may be done in Gateway implementations. Some\nexamples include request or response modification, implementing\nauthentication strategies, rate-limiting, and traffic shaping. API\nguarantee/conformance is defined based on the type of the filter.",
                    "properties": {
                        "extensionRef": {
                            "description": "ExtensionRef is an optional, implementation-specific extension to the\n\"filter\" behavior.  For example, resource \"myroutefilter\" in group\n\"networking.example.net\"). ExtensionRef MUST NOT be used for core and\nextended filters.\n\n\nThis filter can be used multiple times within the same rule.\n\n\nSupport: Implementation-specific",
                            "properties": {
                                "group": {
                                    "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                                    "maxLength": 253,
                                    "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                    "type": "string"
                                },
                                "kind": {
                                    "description": "Kind is kind of the referent. For example \"HTTPRoute\" or \"Service\".",
                                    "maxLength": 63,
                                    "minLength": 1,
                                    "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                                    "type": "string"
                                },
                                "name": {
                                    "description": "Name is the name of the referent.",
                                    "maxLength": 253,
                                    "minLength": 1,
                                    "type": "string"
                                }
                            },
                            "required": [
                                "group",
                                "kind",
                                "name"
                            ],
                            "type": "object"
                        },
                        "requestHeaderModifier": {
                            "description": "RequestHeaderModifier defines a schema for a filter that modifies request\nheaders.\n\n\nSupport: Core",
                            "properties": {
                                "add": {
                                    "description": "Add adds the given header(s) (name, value) to the request\nbefore the action. It appends to any existing values associated\nwith the header name.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  add:\n  - name: \"my-header\"\n    value: \"bar,baz\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: foo,bar,baz",
                                    "items": {
                                        "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                        "properties": {
                                            "name": {
                                                "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                "maxLength": 256,
                                                "minLength": 1,
                                                "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                "type": "string"
                                            },
                                            "value": {
                                                "description": "Value is the value of HTTP Header to be matched.",
                                                "maxLength": 4096,
                                                "minLength": 1,
                                                "type": "string"
                                            }
                                        },
                                        "required": [
                                            "name",
                                            "value"
                                        ],
                                        "type": "object"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-map-keys": [
                                        "name"
                                    ],
                                    "x-kubernetes-list-type": "map"
                                },
                                "remove": {
                                    "description": "Remove the given header(s) from the HTTP request before the action. The\nvalue of Remove is a list of HTTP header names. Note that the header\nnames are case-insensitive (see\nhttps://datatracker.ietf.org/doc/html/rfc2616#section-4.2).\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header1: foo\n  my-header2: bar\n  my-header3: baz\n\n\nConfig:\n  remove: [\"my-header1\", \"my-header3\"]\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header2: bar",
                                    "items": {
                                        "type": "string"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-type": "set"
                                },
                                "set": {
                                    "description": "Set overwrites the request with the given header (name, value)\nbefore the action.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  set:\n  - name: \"my-header\"\n    value: \"bar\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: bar",
                                    "items": {
                                        "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                        "properties": {
                                            "name": {
                                                "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                "maxLength": 256,
                                                "minLength": 1,
                                                "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                "type": "string"
                                            },
                                            "value": {
                                                "description": "Value is the value of HTTP Header to be matched.",
                                                "maxLength": 4096,
                                                "minLength": 1,
                                                "type": "string"
                                            }
                                        },
                                        "required": [
                                            "name",
                                            "value"
                                        ],
                                        "type": "object"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-map-keys": [
                                        "name"
                                    ],
                                    "x-kubernetes-list-type": "map"
                                }
                            },
                            "type": "object"
                        },
                        "requestMirror": {
                            "description": "RequestMirror defines a schema for a filter that mirrors requests.\nRequests are sent to the specified destination, but responses from\nthat destination are ignored.\n\n\nThis filter can be used multiple times within the same rule. Note that\nnot all implementations will be able to support mirroring to multiple\nbackends.\n\n\nSupport: Extended",
                            "properties": {
                                "backendRef": {
                                    "description": "BackendRef references a resource where mirrored requests are sent.\n\n\nMirrored requests must be sent only to a single destination endpoint\nwithin this BackendRef, irrespective of how many endpoints are present\nwithin this BackendRef.\n\n\nIf the referent cannot be found, this BackendRef is invalid and must be\ndropped from the Gateway. The controller must ensure the \"ResolvedRefs\"\ncondition on the Route status is set to `status: False` and not configure\nthis backend in the underlying implementation.\n\n\nIf there is a cross-namespace reference to an *existing* object\nthat is not allowed by a ReferenceGrant, the controller must ensure the\n\"ResolvedRefs\"  condition on the Route is set to `status: False`,\nwith the \"RefNotPermitted\" reason and not configure this backend in the\nunderlying implementation.\n\n\nIn either error case, the Message of the `ResolvedRefs` Condition\nshould be used to provide more detail about the problem.\n\n\nSupport: Extended for Kubernetes Service\n\n\nSupport: Implementation-specific for any other resource",
                                    "properties": {
                                        "group": {
                                            "default": "",
                                            "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                                            "maxLength": 253,
                                            "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                            "type": "string"
                                        },
                                        "kind": {
                                            "default": "Service",
                                            "description": "Kind is the Kubernetes resource kind of the referent. For example\n\"Service\".\n\n\nDefaults to \"Service\" when not specified.\n\n\nExternalName services can refer to CNAME DNS records that may live\noutside of the cluster and as such are difficult to reason about in\nterms of conformance. They also may not be safe to forward to (see\nCVE-2021-25740 for more information). Implementations SHOULD NOT\nsupport ExternalName Services.\n\n\nSupport: Core (Services with a type other than ExternalName)\n\n\nSupport: Implementation-specific (Services with type ExternalName)",
                                            "maxLength": 63,
                                            "minLength": 1,
                                            "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                                            "type": "string"
                                        },
                                        "name": {
                                            "description": "Name is the name of the referent.",
                                            "maxLength": 253,
                                            "minLength": 1,
                                            "type": "string"
                                        },
                                        "namespace": {
                                            "description": "Namespace is the namespace of the backend. When unspecified, the local\nnamespace is inferred.\n\n\nNote that when a namespace different than the local namespace is specified,\na ReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\nSupport: Core",
                                            "maxLength": 63,
                                            "minLength": 1,
                                            "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
                                            "type": "string"
                                        },
                                        "port": {
                                            "description": "Port specifies the destination port number to use for this resource.\nPort is required when the referent is a Kubernetes Service. In this\ncase, the port number is the service port number, not the target port.\nFor other resources, destination port might be derived from the referent\nresource or this field.",
                                            "format": "int32",
                                            "maximum": 65535,
                                            "minimum": 1,
                                            "type": "integer"
                                        }
                                    },
                                    "required": [
                                        "name"
                                    ],
                                    "type": "object",
                                    "x-kubernetes-validations": [
                                        {
                                            "message": "Must have port for Service reference",
                                            "rule": "(size(self.group) == 0 && self.kind == 'Service') ? has(self.port) : true"
                                        }
                                    ]
                                }
                            },
                            "required": [
                                "backendRef"
                            ],
                            "type": "object"
                        },
                        "requestRedirect": {
                            "description": "RequestRedirect defines a schema for a filter that responds to the\nrequest with an HTTP redirection.\n\n\nSupport: Core",
                            "properties": {
                                "hostname": {
                                    "description": "Hostname is the hostname to be used in the value of the `Location`\nheader in the response.\nWhen empty, the hostname in the `Host` header of the request is used.\n\n\nSupport: Core",
                                    "maxLength": 253,
                                    "minLength": 1,
                                    "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                    "type": "string"
                                },
                                "path": {
                                    "description": "Path defines parameters used to modify the path of the incoming request.\nThe modified path is then used to construct the `Location` header. When\nempty, the request path is used as-is.\n\n\nSupport: Extended",
                                    "properties": {
                                        "replaceFullPath": {
                                            "description": "ReplaceFullPath specifies the value with which to replace the full path\nof a request during a rewrite or redirect.",
                                            "maxLength": 1024,
                                            "type": "string"
                                        },
                                        "replacePrefixMatch": {
                                            "description": "ReplacePrefixMatch specifies the value with which to replace the prefix\nmatch of a request during a rewrite or redirect. For example, a request\nto \"/foo/bar\" with a prefix match of \"/foo\" and a ReplacePrefixMatch\nof \"/xyz\" would be modified to \"/xyz/bar\".\n\n\nNote that this matches the behavior of the PathPrefix match type. This\nmatches full path elements. A path element refers to the list of labels\nin the path split by the `/` separator. When specified, a trailing `/` is\nignored. For example, the paths `/abc`, `/abc/`, and `/abc/def` would all\nmatch the prefix `/abc`, but the path `/abcd` would not.\n\n\nReplacePrefixMatch is only compatible with a `PathPrefix` HTTPRouteMatch.\nUsing any other HTTPRouteMatch type on the same HTTPRouteRule will result in\nthe implementation setting the Accepted Condition for the Route to `status: False`.\n\n\nRequest Path | Prefix Match | Replace Prefix | Modified Path\n-------------|--------------|----------------|----------\n/foo/bar     | /foo         | /xyz           | /xyz/bar\n/foo/bar     | /foo         | /xyz/          | /xyz/bar\n/foo/bar     | /foo/        | /xyz           | /xyz/bar\n/foo/bar     | /foo/        | /xyz/          | /xyz/bar\n/foo         | /foo         | /xyz           | /xyz\n/foo/        | /foo         | /xyz           | /xyz/\n/foo/bar     | /foo         | <empty string> | /bar\n/foo/        | /foo         | <empty string> | /\n/foo         | /foo         | <empty string> | /\n/foo/        | /foo         | /              | /\n/foo         | /foo         | /              | /",
                                            "maxLength": 1024,
                                            "type": "string"
                                        },
                                        "type": {
                                            "description": "Type defines the type of path modifier. Additional types may be\nadded in a future release of the API.\n\n\nNote that values may be added to this enum, implementations\nmust ensure that unknown values will not cause a crash.\n\n\nUnknown values here must result in the implementation setting the\nAccepted Condition for the Route to `status: False`, with a\nReason of `UnsupportedValue`.",
                                            "enum": [
                                                "ReplaceFullPath",
                                                "ReplacePrefixMatch"
                                            ],
                                            "type": "string"
                                        }
                                    },
                                    "required": [
                                        "type"
                                    ],
                                    "type": "object",
                                    "x-kubernetes-validations": [
                                        {
                                            "message": "replaceFullPath must be specified when type is set to 'ReplaceFullPath'",
                                            "rule": "self.type == 'ReplaceFullPath' ? has(self.replaceFullPath) : true"
                                        },
                                        {
                                            "message": "type must be 'ReplaceFullPath' when replaceFullPath is set",
                                            "rule": "has(self.replaceFullPath) ? self.type == 'ReplaceFullPath' : true"
                                        },
                                        {
                                            "message": "replacePrefixMatch must be specified when type is set to 'ReplacePrefixMatch'",
                                            "rule": "self.type == 'ReplacePrefixMatch' ? has(self.replacePrefixMatch) : true"
                                        },
                                        {
                                            "message": "type must be 'ReplacePrefixMatch' when replacePrefixMatch is set",
                                            "rule": "has(self.replacePrefixMatch) ? self.type == 'ReplacePrefixMatch' : true"
                                        }
                                    ]
                                },
                                "port": {
                                    "description": "Port is the port to be used in the value of the `Location`\nheader in the response.\n\n\nIf no port is specified, the redirect port MUST be derived using the\nfollowing rules:\n\n\n* If redirect scheme is not-empty, the redirect port MUST be the well-known\n  port associated with the redirect scheme. Specifically \"http\" to port 80\n  and \"https\" to port 443. If the redirect scheme does not have a\n  well-known port, the listener port of the Gateway SHOULD be used.\n* If redirect scheme is empty, the redirect port MUST be the Gateway\n  Listener port.\n\n\nImplementations SHOULD NOT add the port number in the 'Location'\nheader in the following cases:\n\n\n* A Location header that will use HTTP (whether that is determined via\n  the Listener protocol or the Scheme field) _and_ use port 80.\n* A Location header that will use HTTPS (whether that is determined via\n  the Listener protocol or the Scheme field) _and_ use port 443.\n\n\nSupport: Extended",
                                    "format": "int32",
                                    "maximum": 65535,
                                    "minimum": 1,
                                    "type": "integer"
                                },
                                "scheme": {
                                    "description": "Scheme is the scheme to be used in the value of the `Location` header in\nthe response. When empty, the scheme of the request is used.\n\n\nScheme redirects can affect the port of the redirect, for more information,\nrefer to the documentation for the port field of this filter.\n\n\nNote that values may be added to this enum, implementations\nmust ensure that unknown values will not cause a crash.\n\n\nUnknown values here must result in the implementation setting the\nAccepted Condition for the Route to `status: False`, with a\nReason of `UnsupportedValue`.\n\n\nSupport: Extended",
                                    "enum": [
                                        "http",
                                        "https"
                                    ],
                                    "type": "string"
                                },
                                "statusCode": {
                                    "default": 302,
                                    "description": "StatusCode is the HTTP status code to be used in response.\n\n\nNote that values may be added to this enum, implementations\nmust ensure that unknown values will not cause a crash.\n\n\nUnknown values here must result in the implementation setting the\nAccepted Condition for the Route to `status: False`, with a\nReason of `UnsupportedValue`.\n\n\nSupport: Core",
                                    "enum": [
                                        301,
                                        302
                                    ],
                                    "type": "integer"
                                }
                            },
                            "type": "object"
                        },
                        "responseHeaderModifier": {
                            "description": "ResponseHeaderModifier defines a schema for a filter that modifies response\nheaders.\n\n\nSupport: Extended",
                            "properties": {
                                "add": {
                                    "description": "Add adds the given header(s) (name, value) to the request\nbefore the action. It appends to any existing values associated\nwith the header name.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  add:\n  - name: \"my-header\"\n    value: \"bar,baz\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: foo,bar,baz",
                                    "items": {
                                        "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                        "properties": {
                                            "name": {
                                                "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                "maxLength": 256,
                                                "minLength": 1,
                                                "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                "type": "string"
                                            },
                                            "value": {
                                                "description": "Value is the value of HTTP Header to be matched.",
                                                "maxLength": 4096,
                                                "minLength": 1,
                                                "type": "string"
                                            }
                                        },
                                        "required": [
                                            "name",
                                            "value"
                                        ],
                                        "type": "object"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-map-keys": [
                                        "name"
                                    ],
                                    "x-kubernetes-list-type": "map"
                                },
                                "remove": {
                                    "description": "Remove the given header(s) from the HTTP request before the action. The\nvalue of Remove is a list of HTTP header names. Note that the header\nnames are case-insensitive (see\nhttps://datatracker.ietf.org/doc/html/rfc2616#section-4.2).\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header1: foo\n  my-header2: bar\n  my-header3: baz\n\n\nConfig:\n  remove: [\"my-header1\", \"my-header3\"]\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header2: bar",
                                    "items": {
                                        "type": "string"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-type": "set"
                                },
                                "set": {
                                    "description": "Set overwrites the request with the given header (name, value)\nbefore the action.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  set:\n  - name: \"my-header\"\n    value: \"bar\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: bar",
                                    "items": {
                                        "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                        "properties": {
                                            "name": {
                                                "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                "maxLength": 256,
                                                "minLength": 1,
                                                "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                "type": "string"
                                            },
                                            "value": {
                                                "description": "Value is the value of HTTP Header to be matched.",
                                                "maxLength": 4096,
                                                "minLength": 1,
                                                "type": "string"
                                            }
                                        },
                                        "required": [
                                            "name",
                                            "value"
                                        ],
                                        "type": "object"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-map-keys": [
                                        "name"
                                    ],
                                    "x-kubernetes-list-type": "map"
                                }
                            },
                            "type": "object"
                        },
                        "type": {
                            "description": "Type identifies the type of filter to apply. As with other API fields,\ntypes are classified into three conformance levels:\n\n\n- Core: Filter types and their corresponding configuration defined by\n  \"Support: Core\" in this package, e.g. \"RequestHeaderModifier\". All\n  implementations must support core filters.\n\n\n- Extended: Filter types and their corresponding configuration defined by\n  \"Support: Extended\" in this package, e.g. \"RequestMirror\". Implementers\n  are encouraged to support extended filters.\n\n\n- Implementation-specific: Filters that are defined and supported by\n  specific vendors.\n  In the future, filters showing convergence in behavior across multiple\n  implementations will be considered for inclusion in extended or core\n  conformance levels. Filter-specific configuration for such filters\n  is specified using the ExtensionRef field. `Type` should be set to\n  \"ExtensionRef\" for custom filters.\n\n\nImplementers are encouraged to define custom implementation types to\nextend the core API with implementation-specific behavior.\n\n\nIf a reference to a custom filter type cannot be resolved, the filter\nMUST NOT be skipped. Instead, requests that would have been processed by\nthat filter MUST receive a HTTP error response.\n\n\nNote that values may be added to this enum, implementations\nmust ensure that unknown values will not cause a crash.\n\n\nUnknown values here must result in the implementation setting the\nAccepted Condition for the Route to `status: False`, with a\nReason of `UnsupportedValue`.",
                            "enum": [
                                "RequestHeaderModifier",
                                "ResponseHeaderModifier",
                                "RequestMirror",
                                "RequestRedirect",
                                "URLRewrite",
                                "ExtensionRef"
                            ],
                            "type": "string"
                        },
                        "urlRewrite": {
                            "description": "URLRewrite defines a schema for a filter that modifies a request during forwarding.\n\n\nSupport: Extended",
                            "properties": {
                                "hostname": {
                                    "description": "Hostname is the value to be used to replace the Host header value during\nforwarding.\n\n\nSupport: Extended",
                                    "maxLength": 253,
                                    "minLength": 1,
                                    "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                    "type": "string"
                                },
                                "path": {
                                    "description": "Path defines a path rewrite.\n\n\nSupport: Extended",
                                    "properties": {
                                        "replaceFullPath": {
                                            "description": "ReplaceFullPath specifies the value with which to replace the full path\nof a request during a rewrite or redirect.",
                                            "maxLength": 1024,
                                            "type": "string"
                                        },
                                        "replacePrefixMatch": {
                                            "description": "ReplacePrefixMatch specifies the value with which to replace the prefix\nmatch of a request during a rewrite or redirect. For example, a request\nto \"/foo/bar\" with a prefix match of \"/foo\" and a ReplacePrefixMatch\nof \"/xyz\" would be modified to \"/xyz/bar\".\n\n\nNote that this matches the behavior of the PathPrefix match type. This\nmatches full path elements. A path element refers to the list of labels\nin the path split by the `/` separator. When specified, a trailing `/` is\nignored. For example, the paths `/abc`, `/abc/`, and `/abc/def` would all\nmatch the prefix `/abc`, but the path `/abcd` would not.\n\n\nReplacePrefixMatch is only compatible with a `PathPrefix` HTTPRouteMatch.\nUsing any other HTTPRouteMatch type on the same HTTPRouteRule will result in\nthe implementation setting the Accepted Condition for the Route to `status: False`.\n\n\nRequest Path | Prefix Match | Replace Prefix | Modified Path\n-------------|--------------|----------------|----------\n/foo/bar     | /foo         | /xyz           | /xyz/bar\n/foo/bar     | /foo         | /xyz/          | /xyz/bar\n/foo/bar     | /foo/        | /xyz           | /xyz/bar\n/foo/bar     | /foo/        | /xyz/          | /xyz/bar\n/foo         | /foo         | /xyz           | /xyz\n/foo/        | /foo         | /xyz           | /xyz/\n/foo/bar     | /foo         | <empty string> | /bar\n/foo/        | /foo         | <empty string> | /\n/foo         | /foo         | <empty string> | /\n/foo/        | /foo         | /              | /\n/foo         | /foo         | /              | /",
                                            "maxLength": 1024,
                                            "type": "string"
                                        },
                                        "type": {
                                            "description": "Type defines the type of path modifier. Additional types may be\nadded in a future release of the API.\n\n\nNote that values may be added to this enum, implementations\nmust ensure that unknown values will not cause a crash.\n\n\nUnknown values here must result in the implementation setting the\nAccepted Condition for the Route to `status: False`, with a\nReason of `UnsupportedValue`.",
                                            "enum": [
                                                "ReplaceFullPath",
                                                "ReplacePrefixMatch"
                                            ],
                                            "type": "string"
                                        }
                                    },
                                    "required": [
                                        "type"
                                    ],
                                    "type": "object",
                                    "x-kubernetes-validations": [
                                        {
                                            "message": "replaceFullPath must be specified when type is set to 'ReplaceFullPath'",
                                            "rule": "self.type == 'ReplaceFullPath' ? has(self.replaceFullPath) : true"
                                        },
                                        {
                                            "message": "type must be 'ReplaceFullPath' when replaceFullPath is set",
                                            "rule": "has(self.replaceFullPath) ? self.type == 'ReplaceFullPath' : true"
                                        },
                                        {
                                            "message": "replacePrefixMatch must be specified when type is set to 'ReplacePrefixMatch'",
                                            "rule": "self.type == 'ReplacePrefixMatch' ? has(self.replacePrefixMatch) : true"
                                        },
                                        {
                                            "message": "type must be 'ReplacePrefixMatch' when replacePrefixMatch is set",
                                            "rule": "has(self.replacePrefixMatch) ? self.type == 'ReplacePrefixMatch' : true"
                                        }
                                    ]
                                }
                            },
                            "type": "object"
                        }
                    },
                    "required": [
                        "type"
                    ],
                    "type": "object",
                    "x-kubernetes-validations": [
                        {
                            "message": "filter.requestHeaderModifier must be nil if the filter.type is not RequestHeaderModifier",
                            "rule": "!(has(self.requestHeaderModifier) && self.type != 'RequestHeaderModifier')"
                        },
                        {
                            "message": "filter.requestHeaderModifier must be specified for RequestHeaderModifier filter.type",
                            "rule": "!(!has(self.requestHeaderModifier) && self.type == 'RequestHeaderModifier')"
                        },
                        {
                            "message": "filter.responseHeaderModifier must be nil if the filter.type is not ResponseHeaderModifier",
                            "rule": "!(has(self.responseHeaderModifier) && self.type != 'ResponseHeaderModifier')"
                        },
                        {
                            "message": "filter.responseHeaderModifier must be specified for ResponseHeaderModifier filter.type",
                            "rule": "!(!has(self.responseHeaderModifier) && self.type == 'ResponseHeaderModifier')"
                        },
                        {
                            "message": "filter.requestMirror must be nil if the filter.type is not RequestMirror",
                            "rule": "!(has(self.requestMirror) && self.type != 'RequestMirror')"
                        },
                        {
                            "message": "filter.requestMirror must be specified for RequestMirror filter.type",
                            "rule": "!(!has(self.requestMirror) && self.type == 'RequestMirror')"
                        },
                        {
                            "message": "filter.requestRedirect must be nil if the filter.type is not RequestRedirect",
                            "rule": "!(has(self.requestRedirect) && self.type != 'RequestRedirect')"
                        },
                        {
                            "message": "filter.requestRedirect must be specified for RequestRedirect filter.type",
                            "rule": "!(!has(self.requestRedirect) && self.type == 'RequestRedirect')"
                        },
                        {
                            "message": "filter.urlRewrite must be nil if the filter.type is not URLRewrite",
                            "rule": "!(has(self.urlRewrite) && self.type != 'URLRewrite')"
                        },
                        {
                            "message": "filter.urlRewrite must be specified for URLRewrite filter.type",
                            "rule": "!(!has(self.urlRewrite) && self.type == 'URLRewrite')"
                        },
                        {
                            "message": "filter.extensionRef must be nil if the filter.type is not ExtensionRef",
                            "rule": "!(has(self.extensionRef) && self.type != 'ExtensionRef')"
                        },
                        {
                            "message": "filter.extensionRef must be specified for ExtensionRef filter.type",
                            "rule": "!(!has(self.extensionRef) && self.type == 'ExtensionRef')"
                        }
                    ]
                },
                "maxItems": 16,
                "type": "array",
                "x-kubernetes-validations": [
                    {
                        "message": "May specify either httpRouteFilterRequestRedirect or httpRouteFilterRequestRewrite, but not both",
                        "rule": "!(self.exists(f, f.type == 'RequestRedirect') && self.exists(f, f.type == 'URLRewrite'))"
                    },
                    {
                        "message": "RequestHeaderModifier filter cannot be repeated",
                        "rule": "self.filter(f, f.type == 'RequestHeaderModifier').size() <= 1"
                    },
                    {
                        "message": "ResponseHeaderModifier filter cannot be repeated",
                        "rule": "self.filter(f, f.type == 'ResponseHeaderModifier').size() <= 1"
                    },
                    {
                        "message": "RequestRedirect filter cannot be repeated",
                        "rule": "self.filter(f, f.type == 'RequestRedirect').size() <= 1"
                    },
                    {
                        "message": "URLRewrite filter cannot be repeated",
                        "rule": "self.filter(f, f.type == 'URLRewrite').size() <= 1"
                    }
                ]
            },
            "matches": {
                "default": [
                    {
                        "path": {
                            "type": "PathPrefix",
                            "value": "/"
                        }
                    }
                ],
                "description": "Matches define conditions used for matching the rule against incoming\nHTTP requests. Each match is independent, i.e. this rule will be matched\nif **any** one of the matches is satisfied.\n\n\nFor example, take the following matches configuration:\n\n\n```\nmatches:\n- path:\n    value: \"/foo\"\n  headers:\n  - name: \"version\"\n    value: \"v2\"\n- path:\n    value: \"/v2/foo\"\n```\n\n\nFor a request to match against this rule, a request must satisfy\nEITHER of the two conditions:\n\n\n- path prefixed with `/foo` AND contains the header `version: v2`\n- path prefix of `/v2/foo`\n\n\nSee the documentation for HTTPRouteMatch on how to specify multiple\nmatch conditions that should be ANDed together.\n\n\nIf no matches are specified, the default is a prefix\npath match on \"/\", which has the effect of matching every\nHTTP request.\n\n\nProxy or Load Balancer routing configuration generated from HTTPRoutes\nMUST prioritize matches based on the following criteria, continuing on\nties. Across all rules specified on applicable Routes, precedence must be\ngiven to the match having:\n\n\n* \"Exact\" path match.\n* \"Prefix\" path match with largest number of characters.\n* Method match.\n* Largest number of header matches.\n* Largest number of query param matches.\n\n\nNote: The precedence of RegularExpression path matches are implementation-specific.\n\n\nIf ties still exist across multiple Routes, matching precedence MUST be\ndetermined in order of the following criteria, continuing on ties:\n\n\n* The oldest Route based on creation timestamp.\n* The Route appearing first in alphabetical order by\n  \"{namespace}/{name}\".\n\n\nIf ties still exist within an HTTPRoute, matching precedence MUST be granted\nto the FIRST matching rule (in list order) with a match meeting the above\ncriteria.\n\n\nWhen no rules matching a request have been successfully attached to the\nparent a request is coming from, a HTTP 404 status code MUST be returned.",
                "items": {
                    "description": "HTTPRouteMatch defines the predicate used to match requests to a given\naction. Multiple match types are ANDed together, i.e. the match will\nevaluate to true only if all conditions are satisfied.\n\n\nFor example, the match below will match a HTTP request only if its path\nstarts with `/foo` AND it contains the `version: v1` header:\n\n\n```\nmatch:\n\n\n\tpath:\n\t  value: \"/foo\"\n\theaders:\n\t- name: \"version\"\n\t  value \"v1\"\n\n\n```",
                    "properties": {
                        "headers": {
                            "description": "Headers specifies HTTP request header matchers. Multiple match values are\nANDed together, meaning, a request must match all the specified headers\nto select the route.",
                            "items": {
                                "description": "HTTPHeaderMatch describes how to select a HTTP route by matching HTTP request\nheaders.",
                                "properties": {
                                    "name": {
                                        "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, only the first\nentry with an equivalent name MUST be considered for a match. Subsequent\nentries with an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.\n\n\nWhen a header is repeated in an HTTP request, it is\nimplementation-specific behavior as to how this is represented.\nGenerally, proxies should follow the guidance from the RFC:\nhttps://www.rfc-editor.org/rfc/rfc7230.html#section-3.2.2 regarding\nprocessing a repeated header, with special handling for \"Set-Cookie\".",
                                        "maxLength": 256,
                                        "minLength": 1,
                                        "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                        "type": "string"
                                    },
                                    "type": {
                                        "default": "Exact",
                                        "description": "Type specifies how to match against the value of the header.\n\n\nSupport: Core (Exact)\n\n\nSupport: Implementation-specific (RegularExpression)\n\n\nSince RegularExpression HeaderMatchType has implementation-specific\nconformance, implementations can support POSIX, PCRE or any other dialects\nof regular expressions. Please read the implementation's documentation to\ndetermine the supported dialect.",
                                        "enum": [
                                            "Exact",
                                            "RegularExpression"
                                        ],
                                        "type": "string"
                                    },
                                    "value": {
                                        "description": "Value is the value of HTTP Header to be matched.",
                                        "maxLength": 4096,
                                        "minLength": 1,
                                        "type": "string"
                                    }
                                },
                                "required": [
                                    "name",
                                    "value"
                                ],
                                "type": "object"
                            },
                            "maxItems": 16,
                            "type": "array",
                            "x-kubernetes-list-map-keys": [
                                "name"
                            ],
                            "x-kubernetes-list-type": "map"
                        },
                        "method": {
                            "description": "Method specifies HTTP method matcher.\nWhen specified, this route will be matched only if the request has the\nspecified method.\n\n\nSupport: Extended",
                            "enum": [
                                "GET",
                                "HEAD",
                                "POST",
                                "PUT",
                                "DELETE",
                                "CONNECT",
                                "OPTIONS",
                                "TRACE",
                                "PATCH"
                            ],
                            "type": "string"
                        },
                        "path": {
                            "default": {
                                "type": "PathPrefix",
                                "value": "/"
                            },
                            "description": "Path specifies a HTTP request path matcher. If this field is not\nspecified, a default prefix match on the \"/\" path is provided.",
                            "properties": {
                                "type": {
                                    "default": "PathPrefix",
                                    "description": "Type specifies how to match against the path Value.\n\n\nSupport: Core (Exact, PathPrefix)\n\n\nSupport: Implementation-specific (RegularExpression)",
                                    "enum": [
                                        "Exact",
                                        "PathPrefix",
                                        "RegularExpression"
                                    ],
                                    "type": "string"
                                },
                                "value": {
                                    "default": "/",
                                    "description": "Value of the HTTP path to match against.",
                                    "maxLength": 1024,
                                    "type": "string"
                                }
                            },
                            "type": "object",
                            "x-kubernetes-validations": [
                                {
                                    "message": "value must be an absolute path and start with '/' when type one of ['Exact', 'PathPrefix']",
                                    "rule": "(self.type in ['Exact','PathPrefix']) ? self.value.startsWith('/') : true"
                                },
                                {
                                    "message": "must not contain '//' when type one of ['Exact', 'PathPrefix']",
                                    "rule": "(self.type in ['Exact','PathPrefix']) ? !self.value.contains('//') : true"
                                },
                                {
                                    "message": "must not contain '/./' when type one of ['Exact', 'PathPrefix']",
                                    "rule": "(self.type in ['Exact','PathPrefix']) ? !self.value.contains('/./') : true"
                                },
                                {
                                    "message": "must not contain '/../' when type one of ['Exact', 'PathPrefix']",
                                    "rule": "(self.type in ['Exact','PathPrefix']) ? !self.value.contains('/../') : true"
                                },
                                {
                                    "message": "must not contain '%2f' when type one of ['Exact', 'PathPrefix']",
                                    "rule": "(self.type in ['Exact','PathPrefix']) ? !self.value.contains('%2f') : true"
                                },
                                {
                                    "message": "must not contain '%2F' when type one of ['Exact', 'PathPrefix']",
                                    "rule": "(self.type in ['Exact','PathPrefix']) ? !self.value.contains('%2F') : true"
                                },
                                {
                                    "message": "must not contain '#' when type one of ['Exact', 'PathPrefix']",
                                    "rule": "(self.type in ['Exact','PathPrefix']) ? !self.value.contains('#') : true"
                                },
                                {
                                    "message": "must not end with '/..' when type one of ['Exact', 'PathPrefix']",
                                    "rule": "(self.type in ['Exact','PathPrefix']) ? !self.value.endsWith('/..') : true"
                                },
                                {
                                    "message": "must not end with '/.' when type one of ['Exact', 'PathPrefix']",
                                    "rule": "(self.type in ['Exact','PathPrefix']) ? !self.value.endsWith('/.') : true"
                                },
                                {
                                    "message": "type must be one of ['Exact', 'PathPrefix', 'RegularExpression']",
                                    "rule": "self.type in ['Exact','PathPrefix'] || self.type == 'RegularExpression'"
                                },
                                {
                                    "message": "must only contain valid characters (matching ^(?:[-A-Za-z0-9/._~!$&'()*+,;=:@]|[%][0-9a-fA-F]{2})+$) for types ['Exact', 'PathPrefix']",
                                    "rule": "(self.type in ['Exact','PathPrefix']) ? self.value.matches(r\"\"\"^(?:[-A-Za-z0-9/._~!$&'()*+,;=:@]|[%][0-9a-fA-F]{2})+$\"\"\") : true"
                                }
                            ]
                        },
                        "queryParams": {
                            "description": "QueryParams specifies HTTP query parameter matchers. Multiple match\nvalues are ANDed together, meaning, a request must match all the\nspecified query parameters to select the route.\n\n\nSupport: Extended",
                            "items": {
                                "description": "HTTPQueryParamMatch describes how to select a HTTP route by matching HTTP\nquery parameters.",
                                "properties": {
                                    "name": {
                                        "description": "Name is the name of the HTTP query param to be matched. This must be an\nexact string match. (See\nhttps://tools.ietf.org/html/rfc7230#section-2.7.3).\n\n\nIf multiple entries specify equivalent query param names, only the first\nentry with an equivalent name MUST be considered for a match. Subsequent\nentries with an equivalent query param name MUST be ignored.\n\n\nIf a query param is repeated in an HTTP request, the behavior is\npurposely left undefined, since different data planes have different\ncapabilities. However, it is *recommended* that implementations should\nmatch against the first value of the param if the data plane supports it,\nas this behavior is expected in other load balancing contexts outside of\nthe Gateway API.\n\n\nUsers SHOULD NOT route traffic based on repeated query params to guard\nthemselves against potential differences in the implementations.",
                                        "maxLength": 256,
                                        "minLength": 1,
                                        "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                        "type": "string"
                                    },
                                    "type": {
                                        "default": "Exact",
                                        "description": "Type specifies how to match against the value of the query parameter.\n\n\nSupport: Extended (Exact)\n\n\nSupport: Implementation-specific (RegularExpression)\n\n\nSince RegularExpression QueryParamMatchType has Implementation-specific\nconformance, implementations can support POSIX, PCRE or any other\ndialects of regular expressions. Please read the implementation's\ndocumentation to determine the supported dialect.",
                                        "enum": [
                                            "Exact",
                                            "RegularExpression"
                                        ],
                                        "type": "string"
                                    },
                                    "value": {
                                        "description": "Value is the value of HTTP query param to be matched.",
                                        "maxLength": 1024,
                                        "minLength": 1,
                                        "type": "string"
                                    }
                                },
                                "required": [
                                    "name",
                                    "value"
                                ],
                                "type": "object"
                            },
                            "maxItems": 16,
                            "type": "array",
                            "x-kubernetes-list-map-keys": [
                                "name"
                            ],
                            "x-kubernetes-list-type": "map"
                        }
                    },
                    "type": "object"
                },
                "maxItems": 8,
                "type": "array"
            },
            "sessionPersistence": {
                "description": "SessionPersistence defines and configures session persistence\nfor the route rule.\n\n\nSupport: Extended\n\n\n",
                "properties": {
                    "absoluteTimeout": {
                        "description": "AbsoluteTimeout defines the absolute timeout of the persistent\nsession. Once the AbsoluteTimeout duration has elapsed, the\nsession becomes invalid.\n\n\nSupport: Extended",
                        "pattern": "^([0-9]{1,5}(h|m|s|ms)){1,4}$",
                        "type": "string"
                    },
                    "cookieConfig": {
                        "description": "CookieConfig provides configuration settings that are specific\nto cookie-based session persistence.\n\n\nSupport: Core",
                        "properties": {
                            "lifetimeType": {
                                "default": "Session",
                                "description": "LifetimeType specifies whether the cookie has a permanent or\nsession-based lifetime. A permanent cookie persists until its\nspecified expiry time, defined by the Expires or Max-Age cookie\nattributes, while a session cookie is deleted when the current\nsession ends.\n\n\nWhen set to \"Permanent\", AbsoluteTimeout indicates the\ncookie's lifetime via the Expires or Max-Age cookie attributes\nand is required.\n\n\nWhen set to \"Session\", AbsoluteTimeout indicates the\nabsolute lifetime of the cookie tracked by the gateway and\nis optional.\n\n\nSupport: Core for \"Session\" type\n\n\nSupport: Extended for \"Permanent\" type",
                                "enum": [
                                    "Permanent",
                                    "Session"
                                ],
                                "type": "string"
                            }
                        },
                        "type": "object"
                    },
                    "idleTimeout": {
                        "description": "IdleTimeout defines the idle timeout of the persistent session.\nOnce the session has been idle for more than the specified\nIdleTimeout duration, the session becomes invalid.\n\n\nSupport: Extended",
                        "pattern": "^([0-9]{1,5}(h|m|s|ms)){1,4}$",
                        "type": "string"
                    },
                    "sessionName": {
                        "description": "SessionName defines the name of the persistent session token\nwhich may be reflected in the cookie or the header. Users\nshould avoid reusing session names to prevent unintended\nconsequences, such as rejection or unpredictable behavior.\n\n\nSupport: Implementation-specific",
                        "maxLength": 128,
                        "type": "string"
                    },
                    "type": {
                        "default": "Cookie",
                        "description": "Type defines the type of session persistence such as through\nthe use a header or cookie. Defaults to cookie based session\npersistence.\n\n\nSupport: Core for \"Cookie\" type\n\n\nSupport: Extended for \"Header\" type",
                        "enum": [
                            "Cookie",
                            "Header"
                        ],
                        "type": "string"
                    }
                },
                "type": "object",
                "x-kubernetes-validations": [
                    {
                        "message": "AbsoluteTimeout must be specified when cookie lifetimeType is Permanent",
                        "rule": "!has(self.cookieConfig.lifetimeType) || self.cookieConfig.lifetimeType != 'Permanent' || has(self.absoluteTimeout)"
                    }
                ]
            },
            "timeouts": {
                "description": "Timeouts defines the timeouts that can be configured for an HTTP request.\n\n\nSupport: Extended\n\n\n",
                "properties": {
                    "backendRequest": {
                        "description": "BackendRequest specifies a timeout for an individual request from the gateway\nto a backend. This covers the time from when the request first starts being\nsent from the gateway to when the full response has been received from the backend.\n\n\nSetting a timeout to the zero duration (e.g. \"0s\") SHOULD disable the timeout\ncompletely. Implementations that cannot completely disable the timeout MUST\ninstead interpret the zero duration as the longest possible value to which\nthe timeout can be set.\n\n\nAn entire client HTTP transaction with a gateway, covered by the Request timeout,\nmay result in more than one call from the gateway to the destination backend,\nfor example, if automatic retries are supported.\n\n\nBecause the Request timeout encompasses the BackendRequest timeout, the value of\nBackendRequest must be <= the value of Request timeout.\n\n\nSupport: Extended",
                        "pattern": "^([0-9]{1,5}(h|m|s|ms)){1,4}$",
                        "type": "string"
                    },
                    "request": {
                        "description": "Request specifies the maximum duration for a gateway to respond to an HTTP request.\nIf the gateway has not been able to respond before this deadline is met, the gateway\nMUST return a timeout error.\n\n\nFor example, setting the `rules.timeouts.request` field to the value `10s` in an\n`HTTPRoute` will cause a timeout if a client request is taking longer than 10 seconds\nto complete.\n\n\nSetting a timeout to the zero duration (e.g. \"0s\") SHOULD disable the timeout\ncompletely. Implementations that cannot completely disable the timeout MUST\ninstead interpret the zero duration as the longest possible value to which\nthe timeout can be set.\n\n\nThis timeout is intended to cover as close to the whole request-response transaction\nas possible although an implementation MAY choose to start the timeout after the entire\nrequest stream has been received instead of immediately after the transaction is\ninitiated by the client.\n\n\nWhen this field is unspecified, request timeout behavior is implementation-specific.\n\n\nSupport: Extended",
                        "pattern": "^([0-9]{1,5}(h|m|s|ms)){1,4}$",
                        "type": "string"
                    }
                },
                "type": "object",
                "x-kubernetes-validations": [
                    {
                        "message": "backendRequest timeout cannot be longer than request timeout",
                        "rule": "!(has(self.request) && has(self.backendRequest) && duration(self.request) != duration('0s') && duration(self.backendRequest) > duration(self.request))"
                    }
                ]
            }
        },
        "type": "object",
        "x-kubernetes-validations": [
            {
                "message": "RequestRedirect filter must not be used together with backendRefs",
                "rule": "(has(self.backendRefs) && size(self.backendRefs) > 0) ? (!has(self.filters) || self.filters.all(f, !has(f.requestRedirect))): true"
            },
            {
                "message": "When using RequestRedirect filter with path.replacePrefixMatch, exactly one PathPrefix match must be specified",
                "rule": "(has(self.filters) && self.filters.exists_one(f, has(f.requestRedirect) && has(f.requestRedirect.path) && f.requestRedirect.path.type == 'ReplacePrefixMatch' && has(f.requestRedirect.path.replacePrefixMatch))) ? ((size(self.matches) != 1 || !has(self.matches[0].path) || self.matches[0].path.type != 'PathPrefix') ? false : true) : true"
            },
            {
                "message": "When using URLRewrite filter with path.replacePrefixMatch, exactly one PathPrefix match must be specified",
                "rule": "(has(self.filters) && self.filters.exists_one(f, has(f.urlRewrite) && has(f.urlRewrite.path) && f.urlRewrite.path.type == 'ReplacePrefixMatch' && has(f.urlRewrite.path.replacePrefixMatch))) ? ((size(self.matches) != 1 || !has(self.matches[0].path) || self.matches[0].path.type != 'PathPrefix') ? false : true) : true"
            },
            {
                "message": "Within backendRefs, when using RequestRedirect filter with path.replacePrefixMatch, exactly one PathPrefix match must be specified",
                "rule": "(has(self.backendRefs) && self.backendRefs.exists_one(b, (has(b.filters) && b.filters.exists_one(f, has(f.requestRedirect) && has(f.requestRedirect.path) && f.requestRedirect.path.type == 'ReplacePrefixMatch' && has(f.requestRedirect.path.replacePrefixMatch))) )) ? ((size(self.matches) != 1 || !has(self.matches[0].path) || self.matches[0].path.type != 'PathPrefix') ? false : true) : true"
            },
            {
                "message": "Within backendRefs, When using URLRewrite filter with path.replacePrefixMatch, exactly one PathPrefix match must be specified",
                "rule": "(has(self.backendRefs) && self.backendRefs.exists_one(b, (has(b.filters) && b.filters.exists_one(f, has(f.urlRewrite) && has(f.urlRewrite.path) && f.urlRewrite.path.type == 'ReplacePrefixMatch' && has(f.urlRewrite.path.replacePrefixMatch))) )) ? ((size(self.matches) != 1 || !has(self.matches[0].path) || self.matches[0].path.type != 'PathPrefix') ? false : true) : true"
            }
        ]
    },
    "maxItems": 16,
    "type": "array"
}

GRPC_RULES_SCHEMA = {
    "description": "Rules are a list of GRPC matchers, filters and actions.",
    "items": {
        "description": "GRPCRouteRule defines the semantics for matching a gRPC request based on\nconditions (matches), processing it (filters), and forwarding the request to\nan API object (backendRefs).",
        "properties": {
            "backendRefs": {
                "description": "BackendRefs defines the backend(s) where matching requests should be\nsent.\n\n\nFailure behavior here depends on how many BackendRefs are specified and\nhow many are invalid.\n\n\nIf *all* entries in BackendRefs are invalid, and there are also no filters\nspecified in this route rule, *all* traffic which matches this rule MUST\nreceive an `UNAVAILABLE` status.\n\n\nSee the GRPCBackendRef definition for the rules about what makes a single\nGRPCBackendRef invalid.\n\n\nWhen a GRPCBackendRef is invalid, `UNAVAILABLE` statuses MUST be returned for\nrequests that would have otherwise been routed to an invalid backend. If\nmultiple backends are specified, and some are invalid, the proportion of\nrequests that would otherwise have been routed to an invalid backend\nMUST receive an `UNAVAILABLE` status.\n\n\nFor example, if two backends are specified with equal weights, and one is\ninvalid, 50 percent of traffic MUST receive an `UNAVAILABLE` status.\nImplementations may choose how that 50 percent is determined.\n\n\nSupport: Core for Kubernetes Service\n\n\nSupport: Implementation-specific for any other resource\n\n\nSupport for weight: Core",
                "items": {
                    "description": "GRPCBackendRef defines how a GRPCRoute forwards a gRPC request.\n\n\nNote that when a namespace different than the local namespace is specified, a\nReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\n<gateway:experimental:description>\n\n\nWhen the BackendRef points to a Kubernetes Service, implementations SHOULD\nhonor the appProtocol field if it is set for the target Service Port.\n\n\nImplementations supporting appProtocol SHOULD recognize the Kubernetes\nStandard Application Protocols defined in KEP-3726.\n\n\nIf a Service appProtocol isn't specified, an implementation MAY infer the\nbackend protocol through its own means. Implementations MAY infer the\nprotocol from the Route type referring to the backend Service.\n\n\nIf a Route is not able to send traffic to the backend using the specified\nprotocol then the backend is considered invalid. Implementations MUST set the\n\"ResolvedRefs\" condition to \"False\" with the \"UnsupportedProtocol\" reason.\n\n\n</gateway:experimental:description>",
                    "properties": {
                        "filters": {
                            "description": "Filters defined at this level MUST be executed if and only if the\nrequest is being forwarded to the backend defined here.\n\n\nSupport: Implementation-specific (For broader support of filters, use the\nFilters field in GRPCRouteRule.)",
                            "items": {
                                "description": "GRPCRouteFilter defines processing steps that must be completed during the\nrequest or response lifecycle. GRPCRouteFilters are meant as an extension\npoint to express processing that may be done in Gateway implementations. Some\nexamples include request or response modification, implementing\nauthentication strategies, rate-limiting, and traffic shaping. API\nguarantee/conformance is defined based on the type of the filter.",
                                "properties": {
                                    "extensionRef": {
                                        "description": "ExtensionRef is an optional, implementation-specific extension to the\n\"filter\" behavior.  For example, resource \"myroutefilter\" in group\n\"networking.example.net\"). ExtensionRef MUST NOT be used for core and\nextended filters.\n\n\nSupport: Implementation-specific\n\n\nThis filter can be used multiple times within the same rule.",
                                        "properties": {
                                            "group": {
                                                "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                                                "maxLength": 253,
                                                "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                                "type": "string"
                                            },
                                            "kind": {
                                                "description": "Kind is kind of the referent. For example \"HTTPRoute\" or \"Service\".",
                                                "maxLength": 63,
                                                "minLength": 1,
                                                "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                                                "type": "string"
                                            },
                                            "name": {
                                                "description": "Name is the name of the referent.",
                                                "maxLength": 253,
                                                "minLength": 1,
                                                "type": "string"
                                            }
                                        },
                                        "required": [
                                            "group",
                                            "kind",
                                            "name"
                                        ],
                                        "type": "object"
                                    },
                                    "requestHeaderModifier": {
                                        "description": "RequestHeaderModifier defines a schema for a filter that modifies request\nheaders.\n\n\nSupport: Core",
                                        "properties": {
                                            "add": {
                                                "description": "Add adds the given header(s) (name, value) to the request\nbefore the action. It appends to any existing values associated\nwith the header name.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  add:\n  - name: \"my-header\"\n    value: \"bar,baz\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: foo,bar,baz",
                                                "items": {
                                                    "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                                    "properties": {
                                                        "name": {
                                                            "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                            "maxLength": 256,
                                                            "minLength": 1,
                                                            "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                            "type": "string"
                                                        },
                                                        "value": {
                                                            "description": "Value is the value of HTTP Header to be matched.",
                                                            "maxLength": 4096,
                                                            "minLength": 1,
                                                            "type": "string"
                                                        }
                                                    },
                                                    "required": [
                                                        "name",
                                                        "value"
                                                    ],
                                                    "type": "object"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-map-keys": [
                                                    "name"
                                                ],
                                                "x-kubernetes-list-type": "map"
                                            },
                                            "remove": {
                                                "description": "Remove the given header(s) from the HTTP request before the action. The\nvalue of Remove is a list of HTTP header names. Note that the header\nnames are case-insensitive (see\nhttps://datatracker.ietf.org/doc/html/rfc2616#section-4.2).\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header1: foo\n  my-header2: bar\n  my-header3: baz\n\n\nConfig:\n  remove: [\"my-header1\", \"my-header3\"]\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header2: bar",
                                                "items": {
                                                    "type": "string"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-type": "set"
                                            },
                                            "set": {
                                                "description": "Set overwrites the request with the given header (name, value)\nbefore the action.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  set:\n  - name: \"my-header\"\n    value: \"bar\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: bar",
                                                "items": {
                                                    "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                                    "properties": {
                                                        "name": {
                                                            "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                            "maxLength": 256,
                                                            "minLength": 1,
                                                            "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                            "type": "string"
                                                        },
                                                        "value": {
                                                            "description": "Value is the value of HTTP Header to be matched.",
                                                            "maxLength": 4096,
                                                            "minLength": 1,
                                                            "type": "string"
                                                        }
                                                    },
                                                    "required": [
                                                        "name",
                                                        "value"
                                                    ],
                                                    "type": "object"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-map-keys": [
                                                    "name"
                                                ],
                                                "x-kubernetes-list-type": "map"
                                            }
                                        },
                                        "type": "object"
                                    },
                                    "requestMirror": {
                                        "description": "RequestMirror defines a schema for a filter that mirrors requests.\nRequests are sent to the specified destination, but responses from\nthat destination are ignored.\n\n\nThis filter can be used multiple times within the same rule. Note that\nnot all implementations will be able to support mirroring to multiple\nbackends.\n\n\nSupport: Extended",
                                        "properties": {
                                            "backendRef": {
                                                "description": "BackendRef references a resource where mirrored requests are sent.\n\n\nMirrored requests must be sent only to a single destination endpoint\nwithin this BackendRef, irrespective of how many endpoints are present\nwithin this BackendRef.\n\n\nIf the referent cannot be found, this BackendRef is invalid and must be\ndropped from the Gateway. The controller must ensure the \"ResolvedRefs\"\ncondition on the Route status is set to `status: False` and not configure\nthis backend in the underlying implementation.\n\n\nIf there is a cross-namespace reference to an *existing* object\nthat is not allowed by a ReferenceGrant, the controller must ensure the\n\"ResolvedRefs\"  condition on the Route is set to `status: False`,\nwith the \"RefNotPermitted\" reason and not configure this backend in the\nunderlying implementation.\n\n\nIn either error case, the Message of the `ResolvedRefs` Condition\nshould be used to provide more detail about the problem.\n\n\nSupport: Extended for Kubernetes Service\n\n\nSupport: Implementation-specific for any other resource",
                                                "properties": {
                                                    "group": {
                                                        "default": "",
                                                        "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                                                        "maxLength": 253,
                                                        "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                                        "type": "string"
                                                    },
                                                    "kind": {
                                                        "default": "Service",
                                                        "description": "Kind is the Kubernetes resource kind of the referent. For example\n\"Service\".\n\n\nDefaults to \"Service\" when not specified.\n\n\nExternalName services can refer to CNAME DNS records that may live\noutside of the cluster and as such are difficult to reason about in\nterms of conformance. They also may not be safe to forward to (see\nCVE-2021-25740 for more information). Implementations SHOULD NOT\nsupport ExternalName Services.\n\n\nSupport: Core (Services with a type other than ExternalName)\n\n\nSupport: Implementation-specific (Services with type ExternalName)",
                                                        "maxLength": 63,
                                                        "minLength": 1,
                                                        "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                                                        "type": "string"
                                                    },
                                                    "name": {
                                                        "description": "Name is the name of the referent.",
                                                        "maxLength": 253,
                                                        "minLength": 1,
                                                        "type": "string"
                                                    },
                                                    "namespace": {
                                                        "description": "Namespace is the namespace of the backend. When unspecified, the local\nnamespace is inferred.\n\n\nNote that when a namespace different than the local namespace is specified,\na ReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\nSupport: Core",
                                                        "maxLength": 63,
                                                        "minLength": 1,
                                                        "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
                                                        "type": "string"
                                                    },
                                                    "port": {
                                                        "description": "Port specifies the destination port number to use for this resource.\nPort is required when the referent is a Kubernetes Service. In this\ncase, the port number is the service port number, not the target port.\nFor other resources, destination port might be derived from the referent\nresource or this field.",
                                                        "format": "int32",
                                                        "maximum": 65535,
                                                        "minimum": 1,
                                                        "type": "integer"
                                                    }
                                                },
                                                "required": [
                                                    "name"
                                                ],
                                                "type": "object",
                                                "x-kubernetes-validations": [
                                                    {
                                                        "message": "Must have port for Service reference",
                                                        "rule": "(size(self.group) == 0 && self.kind == 'Service') ? has(self.port) : true"
                                                    }
                                                ]
                                            }
                                        },
                                        "required": [
                                            "backendRef"
                                        ],
                                        "type": "object"
                                    },
                                    "responseHeaderModifier": {
                                        "description": "ResponseHeaderModifier defines a schema for a filter that modifies response\nheaders.\n\n\nSupport: Extended",
                                        "properties": {
                                            "add": {
                                                "description": "Add adds the given header(s) (name, value) to the request\nbefore the action. It appends to any existing values associated\nwith the header name.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  add:\n  - name: \"my-header\"\n    value: \"bar,baz\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: foo,bar,baz",
                                                "items": {
                                                    "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                                    "properties": {
                                                        "name": {
                                                            "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                            "maxLength": 256,
                                                            "minLength": 1,
                                                            "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                            "type": "string"
                                                        },
                                                        "value": {
                                                            "description": "Value is the value of HTTP Header to be matched.",
                                                            "maxLength": 4096,
                                                            "minLength": 1,
                                                            "type": "string"
                                                        }
                                                    },
                                                    "required": [
                                                        "name",
                                                        "value"
                                                    ],
                                                    "type": "object"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-map-keys": [
                                                    "name"
                                                ],
                                                "x-kubernetes-list-type": "map"
                                            },
                                            "remove": {
                                                "description": "Remove the given header(s) from the HTTP request before the action. The\nvalue of Remove is a list of HTTP header names. Note that the header\nnames are case-insensitive (see\nhttps://datatracker.ietf.org/doc/html/rfc2616#section-4.2).\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header1: foo\n  my-header2: bar\n  my-header3: baz\n\n\nConfig:\n  remove: [\"my-header1\", \"my-header3\"]\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header2: bar",
                                                "items": {
                                                    "type": "string"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-type": "set"
                                            },
                                            "set": {
                                                "description": "Set overwrites the request with the given header (name, value)\nbefore the action.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  set:\n  - name: \"my-header\"\n    value: \"bar\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: bar",
                                                "items": {
                                                    "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                                    "properties": {
                                                        "name": {
                                                            "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                            "maxLength": 256,
                                                            "minLength": 1,
                                                            "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                            "type": "string"
                                                        },
                                                        "value": {
                                                            "description": "Value is the value of HTTP Header to be matched.",
                                                            "maxLength": 4096,
                                                            "minLength": 1,
                                                            "type": "string"
                                                        }
                                                    },
                                                    "required": [
                                                        "name",
                                                        "value"
                                                    ],
                                                    "type": "object"
                                                },
                                                "maxItems": 16,
                                                "type": "array",
                                                "x-kubernetes-list-map-keys": [
                                                    "name"
                                                ],
                                                "x-kubernetes-list-type": "map"
                                            }
                                        },
                                        "type": "object"
                                    },
                                    "type": {
                                        "description": "Type identifies the type of filter to apply. As with other API fields,\ntypes are classified into three conformance levels:\n\n\n- Core: Filter types and their corresponding configuration defined by\n  \"Support: Core\" in this package, e.g. \"RequestHeaderModifier\". All\n  implementations supporting GRPCRoute MUST support core filters.\n\n\n- Extended: Filter types and their corresponding configuration defined by\n  \"Support: Extended\" in this package, e.g. \"RequestMirror\". Implementers\n  are encouraged to support extended filters.\n\n\n- Implementation-specific: Filters that are defined and supported by specific vendors.\n  In the future, filters showing convergence in behavior across multiple\n  implementations will be considered for inclusion in extended or core\n  conformance levels. Filter-specific configuration for such filters\n  is specified using the ExtensionRef field. `Type` MUST be set to\n  \"ExtensionRef\" for custom filters.\n\n\nImplementers are encouraged to define custom implementation types to\nextend the core API with implementation-specific behavior.\n\n\nIf a reference to a custom filter type cannot be resolved, the filter\nMUST NOT be skipped. Instead, requests that would have been processed by\nthat filter MUST receive a HTTP error response.\n\n\n",
                                        "enum": [
                                            "ResponseHeaderModifier",
                                            "RequestHeaderModifier",
                                            "RequestMirror",
                                            "ExtensionRef"
                                        ],
                                        "type": "string"
                                    }
                                },
                                "required": [
                                    "type"
                                ],
                                "type": "object",
                                "x-kubernetes-validations": [
                                    {
                                        "message": "filter.requestHeaderModifier must be nil if the filter.type is not RequestHeaderModifier",
                                        "rule": "!(has(self.requestHeaderModifier) && self.type != 'RequestHeaderModifier')"
                                    },
                                    {
                                        "message": "filter.requestHeaderModifier must be specified for RequestHeaderModifier filter.type",
                                        "rule": "!(!has(self.requestHeaderModifier) && self.type == 'RequestHeaderModifier')"
                                    },
                                    {
                                        "message": "filter.responseHeaderModifier must be nil if the filter.type is not ResponseHeaderModifier",
                                        "rule": "!(has(self.responseHeaderModifier) && self.type != 'ResponseHeaderModifier')"
                                    },
                                    {
                                        "message": "filter.responseHeaderModifier must be specified for ResponseHeaderModifier filter.type",
                                        "rule": "!(!has(self.responseHeaderModifier) && self.type == 'ResponseHeaderModifier')"
                                    },
                                    {
                                        "message": "filter.requestMirror must be nil if the filter.type is not RequestMirror",
                                        "rule": "!(has(self.requestMirror) && self.type != 'RequestMirror')"
                                    },
                                    {
                                        "message": "filter.requestMirror must be specified for RequestMirror filter.type",
                                        "rule": "!(!has(self.requestMirror) && self.type == 'RequestMirror')"
                                    },
                                    {
                                        "message": "filter.extensionRef must be nil if the filter.type is not ExtensionRef",
                                        "rule": "!(has(self.extensionRef) && self.type != 'ExtensionRef')"
                                    },
                                    {
                                        "message": "filter.extensionRef must be specified for ExtensionRef filter.type",
                                        "rule": "!(!has(self.extensionRef) && self.type == 'ExtensionRef')"
                                    }
                                ]
                            },
                            "maxItems": 16,
                            "type": "array",
                            "x-kubernetes-validations": [
                                {
                                    "message": "RequestHeaderModifier filter cannot be repeated",
                                    "rule": "self.filter(f, f.type == 'RequestHeaderModifier').size() <= 1"
                                },
                                {
                                    "message": "ResponseHeaderModifier filter cannot be repeated",
                                    "rule": "self.filter(f, f.type == 'ResponseHeaderModifier').size() <= 1"
                                }
                            ]
                        },
                        "group": {
                            "default": "",
                            "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                            "maxLength": 253,
                            "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                            "type": "string"
                        },
                        "kind": {
                            "default": "Service",
                            "description": "Kind is the Kubernetes resource kind of the referent. For example\n\"Service\".\n\n\nDefaults to \"Service\" when not specified.\n\n\nExternalName services can refer to CNAME DNS records that may live\noutside of the cluster and as such are difficult to reason about in\nterms of conformance. They also may not be safe to forward to (see\nCVE-2021-25740 for more information). Implementations SHOULD NOT\nsupport ExternalName Services.\n\n\nSupport: Core (Services with a type other than ExternalName)\n\n\nSupport: Implementation-specific (Services with type ExternalName)",
                            "maxLength": 63,
                            "minLength": 1,
                            "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                            "type": "string"
                        },
                        "name": {
                            "description": "Name is the name of the referent.",
                            "maxLength": 253,
                            "minLength": 1,
                            "type": "string"
                        },
                        "namespace": {
                            "description": "Namespace is the namespace of the backend. When unspecified, the local\nnamespace is inferred.\n\n\nNote that when a namespace different than the local namespace is specified,\na ReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\nSupport: Core",
                            "maxLength": 63,
                            "minLength": 1,
                            "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
                            "type": "string"
                        },
                        "port": {
                            "description": "Port specifies the destination port number to use for this resource.\nPort is required when the referent is a Kubernetes Service. In this\ncase, the port number is the service port number, not the target port.\nFor other resources, destination port might be derived from the referent\nresource or this field.",
                            "format": "int32",
                            "maximum": 65535,
                            "minimum": 1,
                            "type": "integer"
                        },
                        "weight": {
                            "default": 1,
                            "description": "Weight specifies the proportion of requests forwarded to the referenced\nbackend. This is computed as weight/(sum of all weights in this\nBackendRefs list). For non-zero values, there may be some epsilon from\nthe exact proportion defined here depending on the precision an\nimplementation supports. Weight is not a percentage and the sum of\nweights does not need to equal 100.\n\n\nIf only one backend is specified and it has a weight greater than 0, 100%\nof the traffic is forwarded to that backend. If weight is set to 0, no\ntraffic should be forwarded for this entry. If unspecified, weight\ndefaults to 1.\n\n\nSupport for this field varies based on the context where used.",
                            "format": "int32",
                            "maximum": 1000000,
                            "minimum": 0,
                            "type": "integer"
                        }
                    },
                    "required": [
                        "name"
                    ],
                    "type": "object",
                    "x-kubernetes-validations": [
                        {
                            "message": "Must have port for Service reference",
                            "rule": "(size(self.group) == 0 && self.kind == 'Service') ? has(self.port) : true"
                        }
                    ]
                },
                "maxItems": 16,
                "type": "array"
            },
            "filters": {
                "description": "Filters define the filters that are applied to requests that match\nthis rule.\n\n\nThe effects of ordering of multiple behaviors are currently unspecified.\nThis can change in the future based on feedback during the alpha stage.\n\n\nConformance-levels at this level are defined based on the type of filter:\n\n\n- ALL core filters MUST be supported by all implementations that support\n  GRPCRoute.\n- Implementers are encouraged to support extended filters.\n- Implementation-specific custom filters have no API guarantees across\n  implementations.\n\n\nSpecifying the same filter multiple times is not supported unless explicitly\nindicated in the filter.\n\n\nIf an implementation can not support a combination of filters, it must clearly\ndocument that limitation. In cases where incompatible or unsupported\nfilters are specified and cause the `Accepted` condition to be set to status\n`False`, implementations may use the `IncompatibleFilters` reason to specify\nthis configuration error.\n\n\nSupport: Core",
                "items": {
                    "description": "GRPCRouteFilter defines processing steps that must be completed during the\nrequest or response lifecycle. GRPCRouteFilters are meant as an extension\npoint to express processing that may be done in Gateway implementations. Some\nexamples include request or response modification, implementing\nauthentication strategies, rate-limiting, and traffic shaping. API\nguarantee/conformance is defined based on the type of the filter.",
                    "properties": {
                        "extensionRef": {
                            "description": "ExtensionRef is an optional, implementation-specific extension to the\n\"filter\" behavior.  For example, resource \"myroutefilter\" in group\n\"networking.example.net\"). ExtensionRef MUST NOT be used for core and\nextended filters.\n\n\nSupport: Implementation-specific\n\n\nThis filter can be used multiple times within the same rule.",
                            "properties": {
                                "group": {
                                    "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                                    "maxLength": 253,
                                    "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                    "type": "string"
                                },
                                "kind": {
                                    "description": "Kind is kind of the referent. For example \"HTTPRoute\" or \"Service\".",
                                    "maxLength": 63,
                                    "minLength": 1,
                                    "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                                    "type": "string"
                                },
                                "name": {
                                    "description": "Name is the name of the referent.",
                                    "maxLength": 253,
                                    "minLength": 1,
                                    "type": "string"
                                }
                            },
                            "required": [
                                "group",
                                "kind",
                                "name"
                            ],
                            "type": "object"
                        },
                        "requestHeaderModifier": {
                            "description": "RequestHeaderModifier defines a schema for a filter that modifies request\nheaders.\n\n\nSupport: Core",
                            "properties": {
                                "add": {
                                    "description": "Add adds the given header(s) (name, value) to the request\nbefore the action. It appends to any existing values associated\nwith the header name.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  add:\n  - name: \"my-header\"\n    value: \"bar,baz\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: foo,bar,baz",
                                    "items": {
                                        "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                        "properties": {
                                            "name": {
                                                "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                "maxLength": 256,
                                                "minLength": 1,
                                                "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                "type": "string"
                                            },
                                            "value": {
                                                "description": "Value is the value of HTTP Header to be matched.",
                                                "maxLength": 4096,
                                                "minLength": 1,
                                                "type": "string"
                                            }
                                        },
                                        "required": [
                                            "name",
                                            "value"
                                        ],
                                        "type": "object"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-map-keys": [
                                        "name"
                                    ],
                                    "x-kubernetes-list-type": "map"
                                },
                                "remove": {
                                    "description": "Remove the given header(s) from the HTTP request before the action. The\nvalue of Remove is a list of HTTP header names. Note that the header\nnames are case-insensitive (see\nhttps://datatracker.ietf.org/doc/html/rfc2616#section-4.2).\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header1: foo\n  my-header2: bar\n  my-header3: baz\n\n\nConfig:\n  remove: [\"my-header1\", \"my-header3\"]\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header2: bar",
                                    "items": {
                                        "type": "string"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-type": "set"
                                },
                                "set": {
                                    "description": "Set overwrites the request with the given header (name, value)\nbefore the action.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  set:\n  - name: \"my-header\"\n    value: \"bar\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: bar",
                                    "items": {
                                        "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                        "properties": {
                                            "name": {
                                                "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                "maxLength": 256,
                                                "minLength": 1,
                                                "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                "type": "string"
                                            },
                                            "value": {
                                                "description": "Value is the value of HTTP Header to be matched.",
                                                "maxLength": 4096,
                                                "minLength": 1,
                                                "type": "string"
                                            }
                                        },
                                        "required": [
                                            "name",
                                            "value"
                                        ],
                                        "type": "object"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-map-keys": [
                                        "name"
                                    ],
                                    "x-kubernetes-list-type": "map"
                                }
                            },
                            "type": "object"
                        },
                        "requestMirror": {
                            "description": "RequestMirror defines a schema for a filter that mirrors requests.\nRequests are sent to the specified destination, but responses from\nthat destination are ignored.\n\n\nThis filter can be used multiple times within the same rule. Note that\nnot all implementations will be able to support mirroring to multiple\nbackends.\n\n\nSupport: Extended",
                            "properties": {
                                "backendRef": {
                                    "description": "BackendRef references a resource where mirrored requests are sent.\n\n\nMirrored requests must be sent only to a single destination endpoint\nwithin this BackendRef, irrespective of how many endpoints are present\nwithin this BackendRef.\n\n\nIf the referent cannot be found, this BackendRef is invalid and must be\ndropped from the Gateway. The controller must ensure the \"ResolvedRefs\"\ncondition on the Route status is set to `status: False` and not configure\nthis backend in the underlying implementation.\n\n\nIf there is a cross-namespace reference to an *existing* object\nthat is not allowed by a ReferenceGrant, the controller must ensure the\n\"ResolvedRefs\"  condition on the Route is set to `status: False`,\nwith the \"RefNotPermitted\" reason and not configure this backend in the\nunderlying implementation.\n\n\nIn either error case, the Message of the `ResolvedRefs` Condition\nshould be used to provide more detail about the problem.\n\n\nSupport: Extended for Kubernetes Service\n\n\nSupport: Implementation-specific for any other resource",
                                    "properties": {
                                        "group": {
                                            "default": "",
                                            "description": "Group is the group of the referent. For example, \"gateway.networking.k8s.io\".\nWhen unspecified or empty string, core API group is inferred.",
                                            "maxLength": 253,
                                            "pattern": "^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
                                            "type": "string"
                                        },
                                        "kind": {
                                            "default": "Service",
                                            "description": "Kind is the Kubernetes resource kind of the referent. For example\n\"Service\".\n\n\nDefaults to \"Service\" when not specified.\n\n\nExternalName services can refer to CNAME DNS records that may live\noutside of the cluster and as such are difficult to reason about in\nterms of conformance. They also may not be safe to forward to (see\nCVE-2021-25740 for more information). Implementations SHOULD NOT\nsupport ExternalName Services.\n\n\nSupport: Core (Services with a type other than ExternalName)\n\n\nSupport: Implementation-specific (Services with type ExternalName)",
                                            "maxLength": 63,
                                            "minLength": 1,
                                            "pattern": "^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$",
                                            "type": "string"
                                        },
                                        "name": {
                                            "description": "Name is the name of the referent.",
                                            "maxLength": 253,
                                            "minLength": 1,
                                            "type": "string"
                                        },
                                        "namespace": {
                                            "description": "Namespace is the namespace of the backend. When unspecified, the local\nnamespace is inferred.\n\n\nNote that when a namespace different than the local namespace is specified,\na ReferenceGrant object is required in the referent namespace to allow that\nnamespace's owner to accept the reference. See the ReferenceGrant\ndocumentation for details.\n\n\nSupport: Core",
                                            "maxLength": 63,
                                            "minLength": 1,
                                            "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
                                            "type": "string"
                                        },
                                        "port": {
                                            "description": "Port specifies the destination port number to use for this resource.\nPort is required when the referent is a Kubernetes Service. In this\ncase, the port number is the service port number, not the target port.\nFor other resources, destination port might be derived from the referent\nresource or this field.",
                                            "format": "int32",
                                            "maximum": 65535,
                                            "minimum": 1,
                                            "type": "integer"
                                        }
                                    },
                                    "required": [
                                        "name"
                                    ],
                                    "type": "object",
                                    "x-kubernetes-validations": [
                                        {
                                            "message": "Must have port for Service reference",
                                            "rule": "(size(self.group) == 0 && self.kind == 'Service') ? has(self.port) : true"
                                        }
                                    ]
                                }
                            },
                            "required": [
                                "backendRef"
                            ],
                            "type": "object"
                        },
                        "responseHeaderModifier": {
                            "description": "ResponseHeaderModifier defines a schema for a filter that modifies response\nheaders.\n\n\nSupport: Extended",
                            "properties": {
                                "add": {
                                    "description": "Add adds the given header(s) (name, value) to the request\nbefore the action. It appends to any existing values associated\nwith the header name.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  add:\n  - name: \"my-header\"\n    value: \"bar,baz\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: foo,bar,baz",
                                    "items": {
                                        "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                        "properties": {
                                            "name": {
                                                "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                "maxLength": 256,
                                                "minLength": 1,
                                                "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                "type": "string"
                                            },
                                            "value": {
                                                "description": "Value is the value of HTTP Header to be matched.",
                                                "maxLength": 4096,
                                                "minLength": 1,
                                                "type": "string"
                                            }
                                        },
                                        "required": [
                                            "name",
                                            "value"
                                        ],
                                        "type": "object"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-map-keys": [
                                        "name"
                                    ],
                                    "x-kubernetes-list-type": "map"
                                },
                                "remove": {
                                    "description": "Remove the given header(s) from the HTTP request before the action. The\nvalue of Remove is a list of HTTP header names. Note that the header\nnames are case-insensitive (see\nhttps://datatracker.ietf.org/doc/html/rfc2616#section-4.2).\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header1: foo\n  my-header2: bar\n  my-header3: baz\n\n\nConfig:\n  remove: [\"my-header1\", \"my-header3\"]\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header2: bar",
                                    "items": {
                                        "type": "string"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-type": "set"
                                },
                                "set": {
                                    "description": "Set overwrites the request with the given header (name, value)\nbefore the action.\n\n\nInput:\n  GET /foo HTTP/1.1\n  my-header: foo\n\n\nConfig:\n  set:\n  - name: \"my-header\"\n    value: \"bar\"\n\n\nOutput:\n  GET /foo HTTP/1.1\n  my-header: bar",
                                    "items": {
                                        "description": "HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.",
                                        "properties": {
                                            "name": {
                                                "description": "Name is the name of the HTTP Header to be matched. Name matching MUST be\ncase insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).\n\n\nIf multiple entries specify equivalent header names, the first entry with\nan equivalent name MUST be considered for a match. Subsequent entries\nwith an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                                "maxLength": 256,
                                                "minLength": 1,
                                                "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                                "type": "string"
                                            },
                                            "value": {
                                                "description": "Value is the value of HTTP Header to be matched.",
                                                "maxLength": 4096,
                                                "minLength": 1,
                                                "type": "string"
                                            }
                                        },
                                        "required": [
                                            "name",
                                            "value"
                                        ],
                                        "type": "object"
                                    },
                                    "maxItems": 16,
                                    "type": "array",
                                    "x-kubernetes-list-map-keys": [
                                        "name"
                                    ],
                                    "x-kubernetes-list-type": "map"
                                }
                            },
                            "type": "object"
                        },
                        "type": {
                            "description": "Type identifies the type of filter to apply. As with other API fields,\ntypes are classified into three conformance levels:\n\n\n- Core: Filter types and their corresponding configuration defined by\n  \"Support: Core\" in this package, e.g. \"RequestHeaderModifier\". All\n  implementations supporting GRPCRoute MUST support core filters.\n\n\n- Extended: Filter types and their corresponding configuration defined by\n  \"Support: Extended\" in this package, e.g. \"RequestMirror\". Implementers\n  are encouraged to support extended filters.\n\n\n- Implementation-specific: Filters that are defined and supported by specific vendors.\n  In the future, filters showing convergence in behavior across multiple\n  implementations will be considered for inclusion in extended or core\n  conformance levels. Filter-specific configuration for such filters\n  is specified using the ExtensionRef field. `Type` MUST be set to\n  \"ExtensionRef\" for custom filters.\n\n\nImplementers are encouraged to define custom implementation types to\nextend the core API with implementation-specific behavior.\n\n\nIf a reference to a custom filter type cannot be resolved, the filter\nMUST NOT be skipped. Instead, requests that would have been processed by\nthat filter MUST receive a HTTP error response.\n\n\n",
                            "enum": [
                                "ResponseHeaderModifier",
                                "RequestHeaderModifier",
                                "RequestMirror",
                                "ExtensionRef"
                            ],
                            "type": "string"
                        }
                    },
                    "required": [
                        "type"
                    ],
                    "type": "object",
                    "x-kubernetes-validations": [
                        {
                            "message": "filter.requestHeaderModifier must be nil if the filter.type is not RequestHeaderModifier",
                            "rule": "!(has(self.requestHeaderModifier) && self.type != 'RequestHeaderModifier')"
                        },
                        {
                            "message": "filter.requestHeaderModifier must be specified for RequestHeaderModifier filter.type",
                            "rule": "!(!has(self.requestHeaderModifier) && self.type == 'RequestHeaderModifier')"
                        },
                        {
                            "message": "filter.responseHeaderModifier must be nil if the filter.type is not ResponseHeaderModifier",
                            "rule": "!(has(self.responseHeaderModifier) && self.type != 'ResponseHeaderModifier')"
                        },
                        {
                            "message": "filter.responseHeaderModifier must be specified for ResponseHeaderModifier filter.type",
                            "rule": "!(!has(self.responseHeaderModifier) && self.type == 'ResponseHeaderModifier')"
                        },
                        {
                            "message": "filter.requestMirror must be nil if the filter.type is not RequestMirror",
                            "rule": "!(has(self.requestMirror) && self.type != 'RequestMirror')"
                        },
                        {
                            "message": "filter.requestMirror must be specified for RequestMirror filter.type",
                            "rule": "!(!has(self.requestMirror) && self.type == 'RequestMirror')"
                        },
                        {
                            "message": "filter.extensionRef must be nil if the filter.type is not ExtensionRef",
                            "rule": "!(has(self.extensionRef) && self.type != 'ExtensionRef')"
                        },
                        {
                            "message": "filter.extensionRef must be specified for ExtensionRef filter.type",
                            "rule": "!(!has(self.extensionRef) && self.type == 'ExtensionRef')"
                        }
                    ]
                },
                "maxItems": 16,
                "type": "array",
                "x-kubernetes-validations": [
                    {
                        "message": "RequestHeaderModifier filter cannot be repeated",
                        "rule": "self.filter(f, f.type == 'RequestHeaderModifier').size() <= 1"
                    },
                    {
                        "message": "ResponseHeaderModifier filter cannot be repeated",
                        "rule": "self.filter(f, f.type == 'ResponseHeaderModifier').size() <= 1"
                    }
                ]
            },
            "matches": {
                "description": "Matches define conditions used for matching the rule against incoming\ngRPC requests. Each match is independent, i.e. this rule will be matched\nif **any** one of the matches is satisfied.\n\n\nFor example, take the following matches configuration:\n\n\n```\nmatches:\n- method:\n    service: foo.bar\n  headers:\n    values:\n      version: 2\n- method:\n    service: foo.bar.v2\n```\n\n\nFor a request to match against this rule, it MUST satisfy\nEITHER of the two conditions:\n\n\n- service of foo.bar AND contains the header `version: 2`\n- service of foo.bar.v2\n\n\nSee the documentation for GRPCRouteMatch on how to specify multiple\nmatch conditions to be ANDed together.\n\n\nIf no matches are specified, the implementation MUST match every gRPC request.\n\n\nProxy or Load Balancer routing configuration generated from GRPCRoutes\nMUST prioritize rules based on the following criteria, continuing on\nties. Merging MUST not be done between GRPCRoutes and HTTPRoutes.\nPrecedence MUST be given to the rule with the largest number of:\n\n\n* Characters in a matching non-wildcard hostname.\n* Characters in a matching hostname.\n* Characters in a matching service.\n* Characters in a matching method.\n* Header matches.\n\n\nIf ties still exist across multiple Routes, matching precedence MUST be\ndetermined in order of the following criteria, continuing on ties:\n\n\n* The oldest Route based on creation timestamp.\n* The Route appearing first in alphabetical order by\n  \"{namespace}/{name}\".\n\n\nIf ties still exist within the Route that has been given precedence,\nmatching precedence MUST be granted to the first matching rule meeting\nthe above criteria.",
                "items": {
                    "description": "GRPCRouteMatch defines the predicate used to match requests to a given\naction. Multiple match types are ANDed together, i.e. the match will\nevaluate to true only if all conditions are satisfied.\n\n\nFor example, the match below will match a gRPC request only if its service\nis `foo` AND it contains the `version: v1` header:\n\n\n```\nmatches:\n  - method:\n    type: Exact\n    service: \"foo\"\n    headers:\n  - name: \"version\"\n    value \"v1\"\n\n\n```",
                    "properties": {
                        "headers": {
                            "description": "Headers specifies gRPC request header matchers. Multiple match values are\nANDed together, meaning, a request MUST match all the specified headers\nto select the route.",
                            "items": {
                                "description": "GRPCHeaderMatch describes how to select a gRPC route by matching gRPC request\nheaders.",
                                "properties": {
                                    "name": {
                                        "description": "Name is the name of the gRPC Header to be matched.\n\n\nIf multiple entries specify equivalent header names, only the first\nentry with an equivalent name MUST be considered for a match. Subsequent\nentries with an equivalent header name MUST be ignored. Due to the\ncase-insensitivity of header names, \"foo\" and \"Foo\" are considered\nequivalent.",
                                        "maxLength": 256,
                                        "minLength": 1,
                                        "pattern": "^[A-Za-z0-9!#$%&'*+\\-.^_\\x60|~]+$",
                                        "type": "string"
                                    },
                                    "type": {
                                        "default": "Exact",
                                        "description": "Type specifies how to match against the value of the header.",
                                        "enum": [
                                            "Exact",
                                            "RegularExpression"
                                        ],
                                        "type": "string"
                                    },
                                    "value": {
                                        "description": "Value is the value of the gRPC Header to be matched.",
                                        "maxLength": 4096,
                                        "minLength": 1,
                                        "type": "string"
                                    }
                                },
                                "required": [
                                    "name",
                                    "value"
                                ],
                                "type": "object"
                            },
                            "maxItems": 16,
                            "type": "array",
                            "x-kubernetes-list-map-keys": [
                                "name"
                            ],
                            "x-kubernetes-list-type": "map"
                        },
                        "method": {
                            "description": "Method specifies a gRPC request service/method matcher. If this field is\nnot specified, all services and methods will match.",
                            "properties": {
                                "method": {
                                    "description": "Value of the method to match against. If left empty or omitted, will\nmatch all services.\n\n\nAt least one of Service and Method MUST be a non-empty string.",
                                    "maxLength": 1024,
                                    "type": "string"
                                },
                                "service": {
                                    "description": "Value of the service to match against. If left empty or omitted, will\nmatch any service.\n\n\nAt least one of Service and Method MUST be a non-empty string.",
                                    "maxLength": 1024,
                                    "type": "string"
                                },
                                "type": {
                                    "default": "Exact",
                                    "description": "Type specifies how to match against the service and/or method.\nSupport: Core (Exact with service and method specified)\n\n\nSupport: Implementation-specific (Exact with method specified but no service specified)\n\n\nSupport: Implementation-specific (RegularExpression)",
                                    "enum": [
                                        "Exact",
                                        "RegularExpression"
                                    ],
                                    "type": "string"
                                }
                            },
                            "type": "object",
                            "x-kubernetes-validations": [
                                {
                                    "message": "One or both of 'service' or 'method' must be specified",
                                    "rule": "has(self.type) ? has(self.service) || has(self.method) : true"
                                },
                                {
                                    "message": "service must only contain valid characters (matching ^(?i)\\.?[a-z_][a-z_0-9]*(\\.[a-z_][a-z_0-9]*)*$)",
                                    "rule": "(!has(self.type) || self.type == 'Exact') && has(self.service) ? self.service.matches(r\"\"\"^(?i)\\.?[a-z_][a-z_0-9]*(\\.[a-z_][a-z_0-9]*)*$\"\"\"): true"
                                },
                                {
                                    "message": "method must only contain valid characters (matching ^[A-Za-z_][A-Za-z_0-9]*$)",
                                    "rule": "(!has(self.type) || self.type == 'Exact') && has(self.method) ? self.method.matches(r\"\"\"^[A-Za-z_][A-Za-z_0-9]*$\"\"\"): true"
                                }
                            ]
                        }
                    },
                    "type": "object"
                },
                "maxItems": 8,
                "type": "array"
            },
            "sessionPersistence": {
                "description": "SessionPersistence defines and configures session persistence\nfor the route rule.\n\n\nSupport: Extended\n\n\n",
                "properties": {
                    "absoluteTimeout": {
                        "description": "AbsoluteTimeout defines the absolute timeout of the persistent\nsession. Once the AbsoluteTimeout duration has elapsed, the\nsession becomes invalid.\n\n\nSupport: Extended",
                        "pattern": "^([0-9]{1,5}(h|m|s|ms)){1,4}$",
                        "type": "string"
                    },
                    "cookieConfig": {
                        "description": "CookieConfig provides configuration settings that are specific\nto cookie-based session persistence.\n\n\nSupport: Core",
                        "properties": {
                            "lifetimeType": {
                                "default": "Session",
                                "description": "LifetimeType specifies whether the cookie has a permanent or\nsession-based lifetime. A permanent cookie persists until its\nspecified expiry time, defined by the Expires or Max-Age cookie\nattributes, while a session cookie is deleted when the current\nsession ends.\n\n\nWhen set to \"Permanent\", AbsoluteTimeout indicates the\ncookie's lifetime via the Expires or Max-Age cookie attributes\nand is required.\n\n\nWhen set to \"Session\", AbsoluteTimeout indicates the\nabsolute lifetime of the cookie tracked by the gateway and\nis optional.\n\n\nSupport: Core for \"Session\" type\n\n\nSupport: Extended for \"Permanent\" type",
                                "enum": [
                                    "Permanent",
                                    "Session"
                                ],
                                "type": "string"
                            }
                        },
                        "type": "object"
                    },
                    "idleTimeout": {
                        "description": "IdleTimeout defines the idle timeout of the persistent session.\nOnce the session has been idle for more than the specified\nIdleTimeout duration, the session becomes invalid.\n\n\nSupport: Extended",
                        "pattern": "^([0-9]{1,5}(h|m|s|ms)){1,4}$",
                        "type": "string"
                    },
                    "sessionName": {
                        "description": "SessionName defines the name of the persistent session token\nwhich may be reflected in the cookie or the header. Users\nshould avoid reusing session names to prevent unintended\nconsequences, such as rejection or unpredictable behavior.\n\n\nSupport: Implementation-specific",
                        "maxLength": 128,
                        "type": "string"
                    },
                    "type": {
                        "default": "Cookie",
                        "description": "Type defines the type of session persistence such as through\nthe use a header or cookie. Defaults to cookie based session\npersistence.\n\n\nSupport: Core for \"Cookie\" type\n\n\nSupport: Extended for \"Header\" type",
                        "enum": [
                            "Cookie",
                            "Header"
                        ],
                        "type": "string"
                    }
                },
                "type": "object",
                "x-kubernetes-validations": [
                    {
                        "message": "AbsoluteTimeout must be specified when cookie lifetimeType is Permanent",
                        "rule": "!has(self.cookieConfig.lifetimeType) || self.cookieConfig.lifetimeType != 'Permanent' || has(self.absoluteTimeout)"
                    }
                ]
            }
        },
        "type": "object"
    },
    "maxItems": 16,
    "type": "array",
}

SCHEMA = {
  "anyOf": [
    TCP_RULES_SCHEMA,
    UDP_RULES_SCHEMA,
    TLS_RULES_SCHEMA,
    HTTP_RULES_SCHEMA,
    GRPC_RULES_SCHEMA,
  ],
  "$schema": "http://json-schema.org/schema#"
}
