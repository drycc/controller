{{/*
Set apiVersion based on .Capabilities.APIVersions
*/}}
{{- define "rbacAPIVersion" -}}
{{- if .Capabilities.APIVersions.Has "rbac.authorization.k8s.io/v1beta1" -}}
rbac.authorization.k8s.io/v1beta1
{{- else if .Capabilities.APIVersions.Has "rbac.authorization.k8s.io/v1alpha1" -}}
rbac.authorization.k8s.io/v1alpha1
{{- else -}}
rbac.authorization.k8s.io/v1
{{- end -}}
{{- end -}}


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
      name: deploy-hook-key
      key: secret-key
{{- end }}
- name: DRYCC_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: django-secret-key
      key: secret-key
- name: DRYCC_BUILDER_KEY
  valueFrom:
    secretKeyRef:
      name: builder-key-auth
      key: builder-key
{{- if eq .Values.global.database_location "off-cluster" }}
- name: DRYCC_DATABASE_NAME
  valueFrom:
    secretKeyRef:
      name: database-creds
      key: name
- name: DRYCC_DATABASE_SERVICE_HOST
  valueFrom:
    secretKeyRef:
      name: database-creds
      key: host
- name: DRYCC_DATABASE_SERVICE_PORT
  valueFrom:
    secretKeyRef:
      name: database-creds
      key: port
{{- end }}
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
- name: WORKFLOW_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{ if eq .Values.global.redis_location "on-cluster"}}
- name: DRYCC_REDIS_ADDRS
  value: "{{range $i := until $redisNodeCount}}drycc-redis-{{$i}}.drycc-redis.{{$.Release.Namespace}}.svc.{{$.Values.global.cluster_domain}}:{{$.Values.redis.port}}{{if lt (add 1 $i) $redisNodeCount}},{{end}}{{end}}"
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
- name: "INFLUXDB_URL"
  valueFrom:
    secretKeyRef:
      name: influxdb-creds
      key: url
{{- else }}
- name: "INFLUXDB_URL"
  value: http://$(DRYCC_INFLUXDB_SERVICE_HOST):$(DRYCC_INFLUXDB_SERVICE_PORT_TRANSPORT)
{{- end }}
- name: "INFLUXDB_BUCKET"
  valueFrom:
    secretKeyRef:
      name: influxdb-creds
      key: bucket
- name: "INFLUXDB_ORG"
  valueFrom:
    secretKeyRef:
      name: influxdb-creds
      key: org
- name: "INFLUXDB_TOKEN"
  valueFrom:
    secretKeyRef:
      name: influxdb-creds
      key: token
{{ if eq .Values.global.rabbitmq_location "off-cluster"}}
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
  value: "amqp://$DRYCC_RABBITMQ_USERNAME:$DRYCC_RABBITMQ_PASSWORD@drycc-rabbitmq-0.drycc-rabbitmq.{{$.Release.Namespace}}.svc.{{$.Values.global.cluster_domain}}:5672/drycc"
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




{{/* Generate controller deployment volumeMounts */}}
{{- define "controller.volumeMounts" -}}
volumeMounts:
  - mountPath: /etc/slugrunner
    name: slugrunner-config
    readOnly: true
{{- end }}

{{/* Generate controller deployment volumes */}}
{{- define "controller.volumes" -}}
volumes:
  - name: rabbitmq-creds
    secret:
      secretName: rabbitmq-creds
  - name: slugrunner-config
    configMap:
      name: slugrunner-config
{{- end }}