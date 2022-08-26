{{/* Generate controller deployment envs */}}
{{- define "controller.envs" }}
env:
- name: REGISTRATION_MODE
  value: {{ .Values.registrationMode }}
# Environmental variable value for $INGRESS_CLASS
- name: "DRYCC_INGRESS_CLASS"
  value: "{{ .Values.global.ingressClass }}"
- name: "DRYCC_PLATFORM_DOMAIN"
  value: "{{ .Values.global.platformDomain }}"
- name: "K8S_API_VERIFY_TLS"
  value: "{{ .Values.k8sApiVerifyTls }}"
- name: "DRYCC_REGISTRY_LOCATION"
  value: "{{ .Values.global.registryLocation }}"
- name: "DRYCC_REGISTRY_SECRET_PREFIX"
  value: "{{ .Values.global.registrySecretPrefix }}"
- name: "IMAGE_PULL_POLICY"
  value: "{{ .Values.appImagePullPolicy }}"
- name: "KUBERNETES_CLUSTER_DOMAIN"
  value: "{{ .Values.global.clusterDomain }}"
{{- if (.Values.appStorageClass) }}
- name: "DRYCC_APP_STORAGE_CLASS"
  value: "{{ .Values.appStorageClass }}"
{{- end }}
{{- if (.Values.appPodExecTimeout) }}
- name: "DRYCC_APP_POD_EXEC_TIMEOUT"
  value: "{{ .Values.appPodExecTimeout }}"
{{- end }}

- name: "TZ"
  value: {{ .Values.time_zone | default "UTC" | quote }}
- name: "DJANGO_SETTINGS_MODULE"
  value: "api.settings.production"
{{- if (.Values.deployHookUrls) }}
- name: DRYCC_DEPLOY_HOOK_URLS
  value: "{{ .Values.deployHookUrls }}"
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
{{- if (.Values.databaseUrl) }}
- name: DRYCC_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: passport-creds
      key: database-url
{{- if (.Values.databaseReplicaUrl) }}
- name: DRYCC_DATABASE_REPLICA_URL
  valueFrom:
    secretKeyRef:
      name: passport-creds
      key: database-replica-url
{{- end }}
{{- else if eq .Values.global.databaseLocation "on-cluster"  }}
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
- name: DRYCC_DATABASE_URL
  value: "postgres://$(DRYCC_DATABASE_USER):$(DRYCC_DATABASE_PASSWORD)@drycc-database.{{.Release.Namespace}}.svc.{{.Values.global.clusterDomain}}:5432/controller"
- name: DRYCC_DATABASE_REPLICA_URL
  value: "postgres://$(DRYCC_DATABASE_USER):$(DRYCC_DATABASE_PASSWORD)@drycc-database-replica.{{.Release.Namespace}}.svc.{{.Values.global.clusterDomain}}:5432/controller"
{{- end }}
- name: WORKFLOW_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
- name: DRYCC_REDIS_ADDRS
  valueFrom:
    secretKeyRef:
      name: redis-creds
      key: addrs
- name: DRYCC_REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: redis-creds
      key: password
{{- if eq .Values.global.influxdbLocation "off-cluster" }}
- name: "DRYCC_INFLUXDB_URL"
  valueFrom:
    secretKeyRef:
      name: influxdb-creds
      key: url
{{- else }}
- name: "DRYCC_INFLUXDB_URL"
  value: http://$(DRYCC_INFLUXDB_SERVICE_HOST):$(DRYCC_INFLUXDB_SERVICE_PORT)
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
{{- if (.Values.rabbitmqUrl) }}
- name: DRYCC_RABBITMQ_URL
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: rabbitmqUrl
{{- else if eq .Values.global.rabbitmqLocation "on-cluster" }}
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
  value: "amqp://$(DRYCC_RABBITMQ_USERNAME):$(DRYCC_RABBITMQ_PASSWORD)@drycc-rabbitmq.{{$.Release.Namespace}}.svc.{{$.Values.global.clusterDomain}}:5672/drycc"
{{- end }}
{{- if eq .Values.global.passportLocation "on-cluster"}}
- name: "DRYCC_PASSPORT_URL"
{{- if .Values.global.certManagerEnabled }}
  value: https://drycc-passport.{{ .Values.global.platformDomain }}
{{- else }}
  value: http://drycc-passport.{{ .Values.global.platformDomain }}
{{- end }}
- name: DRYCC_PASSPORT_KEY
  valueFrom:
    secretKeyRef:
      name: passport-creds
      key: drycc-passport-controller-key
- name: DRYCC_PASSPORT_SECRET
  valueFrom:
    secretKeyRef:
      name: passport-creds
      key: drycc-passport-controller-secret
{{- end }}
{{- range $key, $value := .Values.environment }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}

{{/* Generate controller deployment limits */}}
{{- define "controller.limits" -}}
{{- if or (.Values.limitsCpu) (.Values.limitsMemory) }}
resources:
  limits:
{{- if (.Values.limitsCpu) }}
    cpu: {{.Values.limitsCpu}}
{{- end }}
{{- if (.Values.limitsMemory) }}
    memory: {{.Values.limitsMemory}}
{{- end }}
{{- end }}
{{- end }}
