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
- name: "KUBERNETES_CLUSTER_DOMAIN"
  value: "{{ .Values.global.clusterDomain }}"
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
- name: DRYCC_BUILDER_KEY
  valueFrom:
    secretKeyRef:
      name: builder-key-auth
      key: builder-key
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
  value: "redis://:$(VALKEY_PASSWORD)@drycc-valkey.{{.Release.Namespace}}.svc.{{.Values.global.clusterDomain}}:16379/0"
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
  value: "postgres://$(DRYCC_PG_USER):$(DRYCC_PG_PASSWORD)@drycc-database.{{.Release.Namespace}}.svc.{{.Values.global.clusterDomain}}:5432/controller"
- name: DRYCC_DATABASE_REPLICA_URL
  value: "postgres://$(DRYCC_PG_USER):$(DRYCC_PG_PASSWORD)@drycc-database-replica.{{.Release.Namespace}}.svc.{{.Values.global.clusterDomain}}:5432/controller"
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
{{- if (.Values.victoriametricsUrl) }}
- name: "DRYCC_VICTORIAMETRICS_URL"
  valueFrom:
    secretKeyRef:
      name: controller-creds
      key: victoriametrics-url
{{- else if .Values.victoriametrics.enabled }}
- name: "DRYCC_VICTORIAMETRICS_USERNAME"
  valueFrom:
    secretKeyRef:
      name: victoriametrics-vmauth-creds
      key: username
- name: "DRYCC_VICTORIAMETRICS_PASSWORD"
  valueFrom:
    secretKeyRef:
      name: victoriametrics-vmauth-creds
      key: password
- name: "DRYCC_VICTORIAMETRICS_URL"
  value: "http://$(DRYCC_VICTORIAMETRICS_USERNAME):$(DRYCC_VICTORIAMETRICS_PASSWORD)@drycc-victoriametrics-vmauth.{{$.Release.Namespace}}.svc.{{$.Values.global.clusterDomain}}:8427"
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
{{- $cpus := tuple 1 2 4 8 16 32 64 }}
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
      ephemeral-storage: 4Gi
    requests:
      cpu: {{ divf $cpu 4 }}
      memory: {{ divf $memory 2 }}Gi
      ephemeral-storage: 2Gi
    annotations:
      kubernetes.io/egress-bandwidth: 100M
      kubernetes.io/ingress-bandwidth: 100M
    node_selector: {}
    runtime_class_name: ""
    pod_security_context: {}
    container_security_context: {}
    created: {{ now | date "2006-01-02T15:04:05.000Z" }}
    updated: {{ now | date "2006-01-02T15:04:05.000Z" }}
{{- $index = (add1 $index) }}
{{- end }}
{{- end }}
{{- end }}

{{/* Generate controller config default metrics */}}
{{ define "controller.config.defaultMetrics" }}
container_cpu_load_average_10s: [instance, namespace, pod, container]
container_cpu_system_seconds_total: [instance, namespace, pod, container]
container_cpu_usage_seconds_total: [instance, namespace, pod, container]
container_cpu_user_seconds_total: [instance, namespace, pod, container]
container_cpu_cfs_periods_total: [instance, namespace, pod, container]
container_cpu_cfs_throttled_periods_total: [instance, namespace, pod, container]
container_cpu_cfs_throttled_seconds_total: [instance, namespace, pod, container]
container_fs_inodes_free: [instance, namespace, pod, container]
container_fs_usage_bytes: [instance, namespace, pod, container]
container_fs_inodes_total: [instance, namespace, pod, container]
container_fs_io_current: [instance, namespace, pod, container]
container_fs_io_time_seconds_total: [instance, namespace, pod, container]
container_fs_io_time_weighted_seconds_total: [instance, namespace, pod, container]
container_fs_limit_bytes: [instance, namespace, pod, container]
container_fs_reads_bytes_total: [instance, namespace, pod, container]
container_fs_read_seconds_total: [instance, namespace, pod, container]
container_fs_reads_merged_total: [instance, namespace, pod, container]
container_fs_reads_total: [instance, namespace, pod, container]
container_fs_sector_reads_total: [instance, namespace, pod, container]
container_fs_sector_writes_total: [instance, namespace, pod, container]
container_fs_writes_bytes_total: [instance, namespace, pod, container]
container_fs_write_seconds_total: [instance, namespace, pod, container]
container_fs_writes_merged_total: [instance, namespace, pod, container]
container_fs_writes_total: [instance, namespace, pod, container]
container_blkio_device_usage_total: [instance, namespace, pod, container]
container_memory_failures_total: [instance, namespace, pod, container]
container_memory_failcnt: [instance, namespace, pod, container]
container_memory_cache: [instance, namespace, pod, container]
container_memory_mapped_file: [instance, namespace, pod, container]
container_memory_max_usage_bytes: [instance, namespace, pod, container]
container_memory_rss: [instance, namespace, pod, container]
container_memory_swap: [instance, namespace, pod, container]
container_memory_usage_bytes: [instance, namespace, pod, container]
container_memory_working_set_bytes: [instance, namespace, pod, container]
container_network_receive_bytes_total: [instance, namespace, pod, container]
container_network_receive_errors_total: [instance, namespace, pod, container]
container_network_receive_packets_dropped_total: [instance, namespace, pod, container]
container_network_receive_packets_total: [instance, namespace, pod, container]
container_network_transmit_bytes_total: [instance, namespace, pod, container]
container_network_transmit_errors_total: [instance, namespace, pod, container]
container_network_transmit_packets_dropped_total: [instance, namespace, pod, container]
container_network_transmit_packets_total: [instance, namespace, pod, container]
container_oom_events_total: [instance, namespace, pod, container]
container_processes: [instance, namespace, pod, container]
container_sockets: [instance, namespace, pod, container]
container_file_descriptors: [instance, namespace, pod, container]
container_threads: [instance, namespace, pod, container]
container_threads_max: [instance, namespace, pod, container]
container_ulimits_soft: [instance, namespace, pod, container]
container_spec_cpu_quota: [instance, namespace, pod, container]
container_spec_cpu_period: [instance, namespace, pod, container]
container_spec_cpu_shares: [instance, namespace, pod, container]
container_spec_memory_limit_bytes: [instance, namespace, pod, container]
container_spec_memory_reservation_limit_bytes: [instance, namespace, pod, container]
container_spec_memory_swap_limit_bytes: [instance, namespace, pod, container]
container_start_time_seconds: [instance, namespace, pod, container]
container_tasks_state: [instance, namespace, pod, container]
container_last_seen: [instance, namespace, pod, container]
container_accelerator_memory_used_bytes: [instance, namespace, pod, container]
container_accelerator_memory_total_bytes: [instance, namespace, pod, container]
container_accelerator_duty_cycle: [instance, namespace, pod, container]
kube_pod_ips: [ip, ip_family, namespace, node, pod]
kube_pod_container_status_running: [container, namespace, node, pod]
kube_pod_container_status_ready: [container, namespace, node, pod]
kube_pod_container_status_terminated: [container, namespace, node, pod]
kube_pod_container_status_waiting: [container, namespace, node, pod]
kube_pod_container_status_restarts_total: [container, namespace, node, pod]
kube_pod_spec_volumes_persistentvolumeclaims_info: [namespace, pod, persistentvolumeclaim]
kubelet_volume_stats_used_bytes: [namespace, persistentvolumeclaim, job]
kubelet_volume_stats_available_bytes: [namespace, persistentvolumeclaim, job]
kubelet_volume_stats_capacity_bytes: [namespace, persistentvolumeclaim, job]
kubelet_volume_stats_inodes: [namespace, persistentvolumeclaim, job]
kubelet_volume_stats_inodes_free: [namespace, persistentvolumeclaim, job]
kubelet_volume_stats_inodes_used: [namespace, persistentvolumeclaim, job]
{{- end }}

{{/* Generate controller config default reserved names */}}
{{ define "controller.config.defaultReservedNames" }}
backup
catalog
cert-manager
default
drycc
drycc-manager
drycc-helmbroker
drycc-builder
drycc-grafana
drycc-passport
istio-gateway
istio-system
kube-node-lease
kube-public
kube-system
longhorn-system
metallb
mount-s3
topolvm
rook-ceph
{{- end }}

{{/* Generate controller config default secrets template */}}
{{ define "controller.config.defaultSecretTemplate" }}
oss:
  data:
    key_id: $access_key
    access_key: $secret_key
{{- end }}

{{/* Generate controller config default volume template */}}
{{ define "controller.config.defaultVolumeTemplate" }}
nfs:
  spec:
    capacity:
      storage: 65535Gi
    accessModes:
    - ReadWriteMany
    claimRef:
      namespace: $namespace
      name: $volume_claim_name
    nfs:
      server: $server
      path: $path
    mountOptions:
    - nfsvers=4.2
oss:
  spec:
    capacity:
      storage: 65535Gi
    accessModes:
    - ReadWriteMany
    storageClassName: ''
    claimRef:
      namespace: $namespace
      name: $volume_claim_name
    mountOptions:
    - allow-delete
    - force-path-style
    - endpoint-url $server
    csi:
      driver: s3.csi.aws.com
      volumeHandle: $volume_handle
      volumeAttributes:
        bucketName: $bucket
        authenticationSource: secrets
      nodePublishSecretRef:
        name: $secret_name
        namespace: $namespace
{{- end }}

{{/* Generate controller config default volume claim template */}}
{{ define "controller.config.defaultVolumeClaimTemplate" }}
csi:
  spec:
    accessModes:
    - ReadWriteMany
    storageClassName: $storage_class
    resources:
      requests:
        storage: $size
    volumeMode: Filesystem
nfs:
  spec:
    accessModes:
    - ReadWriteMany
    storageClassName: ''
    resources:
      requests:
        storage: $size
    volumeName: $volume_name
oss:
  spec:
    accessModes:
    - ReadWriteMany
    storageClassName: ''
    resources:
      requests:
        storage: $size
    volumeName: $volume_name
{{- end }}
