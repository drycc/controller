{{/* Generate controller deployment envs */}}
{{- define "controller.envs" }}
env:
- name: VERSION
  value: {{ .Chart.AppVersion }}
- name: REGISTRATION_MODE
  value: {{ .Values.registrationMode }}
- name: "K8S_API_VERIFY_TLS"
  value: "{{ .Values.k8sApiVerifyTls }}"
- name: "DRYCC_REGISTRY_LOCATION"
  value: {{ ternary "on-cluster" "off-cluster" .Values.registry.enabled }}
- name: "DRYCC_REGISTRY_SECRET_PREFIX"
  value: "{{ .Values.registrySecretPrefix }}"
- name: "IMAGE_PULL_POLICY"
  value: "{{ .Values.appImagePullPolicy }}"
- name: "DRYCC_FILER_IMAGE"
  value: "{{ (tpl .Values.filerImage .) }}"
- name: "DRYCC_FILER_IMAGE_PULL_POLICY"
  value: "{{ (tpl .Values.filerImagePullPolicy .) }}"
- name: "DRYCC_APP_GATEWAY_CLASS"
  value: "{{ .Values.appGatewayClass }}"
{{- if (.Values.appStorageClass) }}
- name: "DRYCC_APP_STORAGE_CLASS"
  value: "{{ (tpl .Values.appStorageClass .) }}"
{{- end }}
{{- if (.Values.appDNSPolicy) }}
- name: "DRYCC_APP_DNS_POLICY"
  value: "{{ .Values.appDNSPolicy }}"
{{- end }}
{{- if (.Values.appPodExecTimeout) }}
- name: "DRYCC_APP_POD_EXEC_TIMEOUT"
  value: "{{ .Values.appPodExecTimeout }}"
{{- end }}
- name: "TZ"
  value: {{ .Values.timezone | default "UTC" | quote }}
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
- name: DRYCC_SERVICE_KEY
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: service-key
{{- if (.Values.valkeyUrl) }}
- name: DRYCC_VALKEY_URL
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: valkey-url
{{- else if .Values.valkey.enabled }}
- name: VALKEY_PASSWORD
  valueFrom:
    secretKeyRef:
      name: valkey-creds
      key: password
- name: DRYCC_VALKEY_URL
  value: "redis://:$(VALKEY_PASSWORD)@drycc-valkey:16379/0"
{{- end }}
{{- if (.Values.databaseReplicaUrl) }}
- name: DRYCC_DATABASE_REPLICA_URL
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: database-replica-url
{{- end }}
{{- if (.Values.databaseUrl) }}
- name: DRYCC_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: database-url
{{- else if .Values.database.enabled }}
- name: DRYCC_PG_USER
  valueFrom:
    secretKeyRef:
      name: database-creds
      key: user
- name: DRYCC_PG_PASSWORD
  valueFrom:
    secretKeyRef:
      name: database-creds
      key: password
- name: DRYCC_DATABASE_URL
  value: "postgres://$(DRYCC_PG_USER):$(DRYCC_PG_PASSWORD)@drycc-database:5432/controller"
- name: DRYCC_DATABASE_REPLICA_URL
  value: "postgres://$(DRYCC_PG_USER):$(DRYCC_PG_PASSWORD)@drycc-database-replica:5432/controller"
{{- end }}
{{- if (.Values.workflowManagerUrl) }}
- name: WORKFLOW_MANAGER_URL
  value: "{{ .Values.workflowManagerUrl }}"
- name: WORKFLOW_MANAGER_ACCESS_KEY
  value: "{{ .Values.workflowManagerAccessKey }}"
- name: WORKFLOW_MANAGER_SECRET_KEY
  value: "{{ .Values.workflowManagerSecretKey }}"
{{- end }}
- name: POD_IP
  valueFrom:
    fieldRef:
      fieldPath: status.podIP
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: WORKFLOW_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{- if (.Values.victoriametricsUrl) }}
- name: "DRYCC_VICTORIAMETRICS_URL"
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: victoriametrics-url
{{- else if .Values.victoriametrics.enabled }}
- name: "DRYCC_VICTORIAMETRICS_URL"
  value: "http://drycc-victoriametrics-vmselect:8481/select/multitenant/prometheus"
{{- end }}
{{- if .Values.passport.enabled }}
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
{{- else }}
- name: DRYCC_PASSPORT_URL
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: passport-url
- name: DRYCC_PASSPORT_KEY
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: passport-key
- name: DRYCC_PASSPORT_SECRET
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: passport-secret
{{- end }}
- name: QUICKWIT_INDEXER_URL
  value: http://drycc-quickwit-indexer:7280
- name: QUICKWIT_SEARCHER_URL
  value: http://drycc-quickwit-searcher:7280
- name: QUICKWIT_LOG_INDEX_PREFIX
  value: {{ .Values.quickwit.logIndexPrefix }}
{{- range $key, $value := .Values.environment }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}

{{- define "controller-job.envs" }}
{{- include "controller.envs" . }}
- name: DRYCC_DATABASE_ROUTERS
  value: api.routers.DefaultReplicaRouter
{{- end }}

{{- define "controller-api.envs" }}
{{- include "controller.envs" . }}
- name: DRYCC_CONTROLLER_RUNNER
  value: api
{{- end }}

{{- define "controller-metric.envs" }}
{{- include "controller.envs" . }}
- name: DRYCC_CONTROLLER_RUNNER
  value: metric
{{- end }}

{{- define "controller-mutate.envs" }}
{{- include "controller.envs" . }}
- name: DRYCC_CONTROLLER_RUNNER
  value: mutate
{{- end }}
