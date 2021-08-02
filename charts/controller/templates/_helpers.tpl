{{/* Generate controller deployment envs */}}
{{- define "controller.envs" -}}
{{ $redisNodeCount := .Values.redis.replicas | int }}
env:
- name: REGISTRATION_MODE
  value: {{ .Values.registration_mode }}
# NOTE(bacongobbler): use drycc/registry_proxy to work around Docker --insecure-registry requirements
- name: "DRYCC_REGISTRY_PROXY_HOST"
  value: "127.0.0.1"
# Environmental variable value for $INGRESS_CLASS
- name: "DRYCC_INGRESS_CLASS"
  value: "{{ .Values.global.ingress_class }}"
- name: "DRYCC_PLATFORM_DOMAIN"
  value: "{{ .Values.global.platform_domain }}"
- name: "K8S_API_VERIFY_TLS"
  value: "{{ .Values.k8s_api_verify_tls }}"
- name: "DRYCC_REGISTRY_PROXY_PORT"
  value: "{{ .Values.global.registry_proxy_port }}"
- name: "APP_STORAGE"
  value: "{{ .Values.global.storage}}"
- name: "DRYCC_REGISTRY_LOCATION"
  value: "{{ .Values.global.registry_location }}"
- name: "DRYCC_REGISTRY_SECRET_PREFIX"
  value: "{{ .Values.global.registry_secret_prefix }}"
- name: "IMAGE_PULL_POLICY"
  value: "{{ .Values.app_image_pull_policy }}"
- name: "KUBERNETES_CLUSTER_DOMAIN"
  value: "{{ .Values.global.cluster_domain }}"
{{- if (.Values.app_storage_class) }}
- name: "DRYCC_APP_STORAGE_CLASS"
  value: "{{ .Values.app_storage_class }}"
{{- end }}
- name: "TZ"
  value: {{ .Values.time_zone | default "UTC" | quote }}
{{- if (.Values.deploy_hook_urls) }}
- name: DRYCC_DEPLOY_HOOK_URLS
  value: "{{ .Values.deploy_hook_urls }}"
- name: DRYCC_DEPLOY_HOOK_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: deploy-hook-secret-key
{{- end }}
- name: DRYCC_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: django-secret-key
- name: DRYCC_BUILDER_KEY
  valueFrom:
    secretKeyRef:
      name: builder-key-auth
      key: builder-key
{{- if (.Values.database_url) }}
- name: DRYCC_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: database_url
{{- else if eq .Values.global.database_location "on-cluster"  }}
- name: DRYCC_DATABASE_USER
  valueFrom:
    secretKeyRef:
      name: database-creds
      key: user
- name: DRYCC_DATABASE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: database-creds
      key: password
- name: DRYCC_DATABASE_NAME
  valueFrom:
    secretKeyRef:
      name: database-creds
      key: controller-database-name
- name: DRYCC_DATABASE_URL
  value: "postgres://$(DRYCC_DATABASE_USER):$(DRYCC_DATABASE_PASSWORD)@$(DRYCC_DATABASE_SERVICE_HOST):$(DRYCC_DATABASE_SERVICE_PORT)/$(DRYCC_DATABASE_NAME)"
{{- end }}
- name: WORKFLOW_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{- if eq .Values.global.redis_location "on-cluster"}}
- name: DRYCC_REDIS_ADDRS
  value: "{{range $i := until $redisNodeCount}}drycc-redis-{{$i}}.drycc-redis.{{$.Release.Namespace}}.svc.{{$.Values.global.cluster_domain}}:6379{{if lt (add 1 $i) $redisNodeCount}},{{end}}{{end}}"
{{- else if eq .Values.global.redis_location "off-cluster" }}
- name: DRYCC_REDIS_ADDRS
  valueFrom:
    secretKeyRef:
      name: redis-creds
      key: addrs
{{- end }}
- name: DRYCC_REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: redis-creds
      key: password
{{- if eq .Values.global.influxdb_location "off-cluster" }}
- name: "DRYCC_INFLUXDB_URL"
  valueFrom:
    secretKeyRef:
      name: influxdb-creds
      key: url
{{- else }}
- name: "DRYCC_INFLUXDB_URL"
  value: http://$(DRYCC_INFLUXDB_SERVICE_HOST):$(DRYCC_INFLUXDB_SERVICE_PORT_TRANSPORT)
{{- end }}
- name: "DRYCC_INFLUXDB_BUCKET"
  valueFrom:
    secretKeyRef:
      name: influxdb-creds
      key: bucket
- name: "DRYCC_INFLUXDB_ORG"
  valueFrom:
    secretKeyRef:
      name: influxdb-creds
      key: org
- name: "DRYCC_INFLUXDB_TOKEN"
  valueFrom:
    secretKeyRef:
      name: influxdb-creds
      key: token
{{- if eq .Values.global.rabbitmq_location "off-cluster"}}
- name: "DRYCC_RABBITMQ_URL"
  valueFrom:
    secretKeyRef:
      name: rabbitmq-creds
      key: url
{{- else if eq .Values.global.rabbitmq_location "on-cluster" }}
- name: "DRYCC_RABBITMQ_USERNAME"
  valueFrom:
    secretKeyRef:
      name: rabbitmq-creds
      key: username
- name: "DRYCC_RABBITMQ_PASSWORD"
  valueFrom:
    secretKeyRef:
      name: rabbitmq-creds
      key: password
- name: "DRYCC_RABBITMQ_URL"
  value: "amqp://$(DRYCC_RABBITMQ_USERNAME):$(DRYCC_RABBITMQ_PASSWORD)@drycc-rabbitmq-0.drycc-rabbitmq.{{$.Release.Namespace}}.svc.{{$.Values.global.cluster_domain}}:5672/drycc"
{{- end }}
{{- if eq .Values.global.passport_location "on-cluster"}}
- name: "DRYCC_PASSPORT_DOMAIN"
  value: http://drycc-passport.{{ .Values.global.platform_domain }}
- name: "SOCIAL_AUTH_DRYCC_AUTHORIZATION_URL"
  value: "$(DRYCC_PASSPORT_DOMAIN)/oauth/authorize/"
- name: "SOCIAL_AUTH_DRYCC_ACCESS_TOKEN_URL"
  value: "$(DRYCC_PASSPORT_DOMAIN)/oauth/token/"
- name: "SOCIAL_AUTH_DRYCC_ACCESS_API_URL"
  value: "$(DRYCC_PASSPORT_DOMAIN)/users/"
- name: "SOCIAL_AUTH_DRYCC_USERINFO_URL"
  value: "$(DRYCC_PASSPORT_DOMAIN)/oauth/userinfo/"
- name: "SOCIAL_AUTH_DRYCC_JWKS_URI"
  value: "$(DRYCC_PASSPORT_DOMAIN)/oauth/.well-known/jwks.json"
- name: "SOCIAL_AUTH_DRYCC_OIDC_ENDPOINT"
  value: "$(DRYCC_PASSPORT_DOMAIN)/oauth"
- name: "LOGIN_REDIRECT_URL"
  value: "$(DRYCC_PASSPORT_DOMAIN)/login/done/"
- name: SOCIAL_AUTH_DRYCC_CONTROLLER_KEY
  valueFrom:
    secretKeyRef:
      name: passport-creds
      key: social-auth-drycc-controller-key
- name: SOCIAL_AUTH_DRYCC_CONTROLLER_SECRET
  valueFrom:
    secretKeyRef:
      name: passport-creds
      key: social-auth-drycc-controller-secret
{{- end }}
{{- range $key, $value := .Values.environment }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}


{{/* Generate controller deployment limits */}}
{{- define "controller.limits" -}}
{{- if or (.Values.limits_cpu) (.Values.limits_memory) }}
resources:
  limits:
{{- if (.Values.limits_cpu) }}
    cpu: {{.Values.limits_cpu}}
{{- end }}
{{- if (.Values.limits_memory) }}
    memory: {{.Values.limits_memory}}
{{- end }}
{{- end }}
{{- end }}
