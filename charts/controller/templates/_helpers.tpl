{{/* Generate controller deployment envs */}}
{{- define "controller.envs" }}
env:
- name: VERSION
  value: {{ .Chart.AppVersion }}
- name: REGISTRATION_MODE
  value: {{ .Values.registrationMode }}
# Environmental variable value for $GATEWAY_CLASS
- name: "DRYCC_GATEWAY_CLASS"
  value: "{{ .Values.global.gatewayClass }}"
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
  value: "{{ (tpl .Values.appStorageClass .) }}"
{{- end }}
{{- if (.Values.appRuntimeClass) }}
- name: "DRYCC_APP_RUNTIME_CLASS"
  value: "{{ .Values.appRuntimeClass }}"
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
- name: DRYCC_BUILDER_KEY
  valueFrom:
    secretKeyRef:
      name: builder-key-auth
      key: builder-key
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
{{- else if eq .Values.global.databaseLocation "on-cluster"  }}
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
  value: "postgres://$(DRYCC_PG_USER):$(DRYCC_PG_PASSWORD)@drycc-database.{{.Release.Namespace}}.svc.{{.Values.global.clusterDomain}}:5432/controller"
- name: DRYCC_DATABASE_REPLICA_URL
  value: "postgres://$(DRYCC_PG_USER):$(DRYCC_PG_PASSWORD)@drycc-database-replica.{{.Release.Namespace}}.svc.{{.Values.global.clusterDomain}}:5432/controller"
{{- end }}
{{- if (.Values.databaseMonitorUrl) }}
- name: DRYCC_DATABASE_MONITOR_URL
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: database-monitor-url
{{- else if eq .Values.global.timeseriesLocation "on-cluster"  }}
- name: DRYCC_TS_USER
  valueFrom:
    secretKeyRef:
      name: timeseries-creds
      key: user
- name: DRYCC_TS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: timeseries-creds
      key: password
- name: DRYCC_DATABASE_MONITOR_URL
  value: "postgres://$(DRYCC_TS_USER):$(DRYCC_TS_PASSWORD)@drycc-timeseries-replica.{{.Release.Namespace}}.svc.{{.Values.global.clusterDomain}}:5432/monitor"
{{- end }}
{{- if (.Values.workflowManagerUrl) }}
- name: WORKFLOW_MANAGER_URL
  value: "{{ .Values.workflowManagerUrl }}"
- name: WORKFLOW_MANAGER_ACCESS_KEY
  value: "{{ .Values.workflowManagerAccessKey }}"
- name: WORKFLOW_MANAGER_SECRET_KEY
  value: "{{ .Values.workflowManagerSecretKey }}"
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
{{- if eq .Values.global.rabbitmqLocation "off-cluster" }}
- name: "DRYCC_PROMETHEUS_URL"
  valueFrom:
    secretKeyRef:
      name: prometheus-creds
      key: url
{{- else }}
- name: "DRYCC_PROMETHEUS_USERNAME"
  valueFrom:
    secretKeyRef:
      name: prometheus-creds
      key: username
- name: "DRYCC_PROMETHEUS_PASSWORD"
  valueFrom:
    secretKeyRef:
      name: prometheus-creds
      key: password
- name: "DRYCC_PROMETHEUS_URL"
  value: "http://$(DRYCC_PROMETHEUS_USERNAME):$(DRYCC_PROMETHEUS_PASSWORD)@drycc-prometheus.{{$.Release.Namespace}}.svc.{{$.Values.global.clusterDomain}}:9090"
{{- end }}
{{- if (.Values.rabbitmqUrl) }}
- name: DRYCC_RABBITMQ_URL
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: rabbitmq-url
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

{{/* Generate controller config default limit specs */}}
{{ define "controller.config.defaultLimitSpecs" }}
- model: api.limitspec
  pk: std1
  fields:
    cpu:
      name: Universal CPU
      cores: 32
      clock: 3100MHZ
      boost: 3700MHZ
      threads: 64
    memory:
      size: 64GB
      type: DDR4-ECC
    features:
      gpu:
        name: Integrated GPU
        tmus: 1
        rops: 1
        cores: 128
        memory:
          size: shared
          type: shared
      network: 10G
    keywords:
    - unknown
    disabled: false
    created: {{ now | date "2006-01-02T15:04:05.000Z" }}
    updated: {{ now | date "2006-01-02T15:04:05.000Z" }}
{{- end }}

{{/* Generate controller config default limit plans */}}
{{ define "controller.config.defaultLimitPlans" }}
{{- $index := 0 }}
{{- $cpus := tuple 1 2 4 8 16 32 }}
{{- $scales := tuple 1 2 4 8 }}
{{- range $cpu := $cpus }}
{{- range $scale := $scales }}
{{- $memory := mul $cpu $scale }}
- model: api.limitplan
  pk: std1.large.c{{ $cpu }}m{{ $memory }}
  fields:
    spec_id: std1
    cpu: {{ $cpu }}
    memory: {{ $memory }}
    features:
      gpu: 1
      network: 1
    disabled: false
    priority: {{ add 10000 (mul (add1 $index) 100) }}
    limits:
      cpu: {{ $cpu }}
      memory: {{ $memory }}Gi
      ephemeral-storage: 2Gi
    requests:
      cpu: {{ divf $cpu 4 }}
      memory: {{ divf $memory 2 }}Gi
      ephemeral-storage: 2Gi
    annotations:
      kubernetes.io/egress-bandwidth: 100M
      kubernetes.io/ingress-bandwidth: 100M
    node_selector: {}
    pod_security_context: {}
    container_security_context: {}
    created: {{ now | date "2006-01-02T15:04:05.000Z" }}
    updated: {{ now | date "2006-01-02T15:04:05.000Z" }}
{{- $index = (add1 $index) }}
{{- end }}
{{- end }}
{{- end }}
