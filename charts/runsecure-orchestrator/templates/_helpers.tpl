{{/*
_helpers.tpl — named template helpers for runsecure-orchestrator
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "runsecure-orchestrator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "runsecure-orchestrator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label value: name-version.
*/}}
{{- define "runsecure-orchestrator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every object.
*/}}
{{- define "runsecure-orchestrator.labels" -}}
helm.sh/chart: {{ include "runsecure-orchestrator.chart" . }}
{{ include "runsecure-orchestrator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
runsecure.io/scope: {{ .Values.scope.name | quote }}
{{- end }}

{{/*
Selector labels (stable across upgrades).
*/}}
{{- define "runsecure-orchestrator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "runsecure-orchestrator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "runsecure-orchestrator.serviceAccountName" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- include "runsecure-orchestrator.fullname" . }}
{{- end }}
{{- end }}

{{/*
Orchestrator namespace: runsecure-<scope>.
*/}}
{{- define "runsecure-orchestrator.namespace" -}}
{{- printf "runsecure-%s" .Values.scope.name }}
{{- end }}

{{/*
Immutable image reference (repository@digest). The values schema requires a
real sha256 digest; tags are retained only as release metadata.
*/}}
{{- define "runsecure-orchestrator.imageRef" -}}
{{- printf "%s@%s" .repository .digest }}
{{- end }}

{{/* Orchestrator image reference. */}}
{{- define "runsecure-orchestrator.image" -}}
{{- include "runsecure-orchestrator.imageRef" .Values.image.orchestrator }}
{{- end }}

{{/*
PAT secret name — either an existing one or the chart-managed one.
*/}}
{{- define "runsecure-orchestrator.patSecretName" -}}
{{- if .Values.auth.pat.existingSecretName }}
{{- .Values.auth.pat.existingSecretName }}
{{- else }}
{{- printf "%s-pat" (include "runsecure-orchestrator.fullname" .) }}
{{- end }}
{{- end }}

{{/*
GitHub App private-key secret name.
*/}}
{{- define "runsecure-orchestrator.appPrivKeySecretName" -}}
{{- if .Values.auth.app.privateKeySecretName }}
{{- .Values.auth.app.privateKeySecretName }}
{{- else }}
{{- printf "%s-app-key" (include "runsecure-orchestrator.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Self-signed cert-manager Issuer name.
*/}}
{{- define "runsecure-orchestrator.selfSignedIssuerName" -}}
{{- printf "%s-selfsigned" (include "runsecure-orchestrator.fullname" .) }}
{{- end }}

{{/*
Issuer name to use in the Certificate: self-signed or user-provided.
*/}}
{{- define "runsecure-orchestrator.issuerName" -}}
{{- if .Values.tls.selfSigned }}
{{- include "runsecure-orchestrator.selfSignedIssuerName" . }}
{{- else }}
{{- .Values.tls.issuerName }}
{{- end }}
{{- end }}

{{/* Validate enrollment before rendering any runtime resources. */}}
{{- define "runsecure-orchestrator.validateProjects" -}}
{{- $shared := false -}}
{{- range .Values.scope.repos -}}{{- if or .namespace (hasKey . "runnerConfig") (hasKey . "runnerImage") (hasKey . "kubernetes") -}}{{- $shared = true -}}{{- end -}}{{- end -}}
{{- $repos := dict -}}{{- $namespaces := dict -}}
{{- range .Values.scope.repos -}}
{{- if hasKey $repos (lower .repo) -}}{{- fail "duplicate repository enrollment" -}}{{- end -}}
{{- $_ := set $repos (lower .repo) true -}}
{{- if $shared -}}
{{- if eq $.Values.image.orchestrator.digest "sha256:dca28cce796ea6b05da390b39d7822ad0fe6bbb91bc3485de10324cbf75dca97" -}}{{- fail "shared mode requires an explicitly pinned RunSecure 2.2+ controller from the approved release manifest; bundled 2.1.10 controller is incompatible" -}}{{- end -}}
{{- if ne $.Values.scope.backend "kube" -}}{{- fail "shared namespaces require kube backend" -}}{{- end -}}
{{- if or (not .namespace) (not .runnerConfig) -}}{{- fail "all shared projects require namespace and approved runnerConfig" -}}{{- end -}}
{{- if or (eq .namespace "default") (hasPrefix "kube-" .namespace) (eq .namespace (include "runsecure-orchestrator.namespace" $)) (hasKey $namespaces .namespace) -}}{{- fail "reserved, controller or duplicate project namespace" -}}{{- end -}}
{{- $_ := set $namespaces .namespace true -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Convert chart camelCase runner values into canonical source YAML. */}}
{{- define "runsecure-orchestrator.runnerConfig" -}}
{{- $runner := dict "runtime" .runtime "labels" .labels "resources" .resources -}}
{{- range $from, $to := dict "version" "version" "httpEgress" "http_egress" "tcpEgress" "tcp_egress" -}}
{{- if hasKey $ $from -}}{{- $_ := set $runner $to (get $ $from) -}}{{- end -}}
{{- end -}}
{{- if .orchestrator -}}
{{- $orchestrator := dict -}}
{{- range $from, $to := dict "timeoutSeconds" "timeout_seconds" "securityOverrides" "security_overrides" -}}
{{- if hasKey $.orchestrator $from -}}{{- $_ := set $orchestrator $to (get $.orchestrator $from) -}}{{- end -}}
{{- end -}}
{{- $_ := set $runner "orchestrator" $orchestrator -}}
{{- end -}}
{{- if .dns -}}{{- $_ := set $runner "dns" .dns -}}{{- end -}}
{{- toYaml $runner -}}
{{- end -}}

{{- define "runsecure-orchestrator.podSettings" -}}
{{- $settings := dict -}}
{{- range $from, $to := dict "nodeSelector" "node_selector" "ephemeralStorage" "ephemeral_storage" -}}
{{- if hasKey $ $from -}}{{- $_ := set $settings $to (get $ $from) -}}{{- end -}}
{{- end -}}
{{- if .proxyResources -}}
{{- $proxy := dict -}}
{{- range $from, $to := dict "cpu" "cpu" "memory" "memory" "ephemeralStorage" "ephemeral_storage" -}}
{{- if hasKey $.proxyResources $from -}}{{- $_ := set $proxy $to (get $.proxyResources $from) -}}{{- end -}}
{{- end -}}
{{- $_ := set $settings "proxy_resources" $proxy -}}
{{- end -}}
{{- if .tolerations -}}
{{- $tolerations := list -}}
{{- range .tolerations -}}
{{- $toleration := omit . "tolerationSeconds" -}}
{{- if hasKey . "tolerationSeconds" -}}{{- $_ := set $toleration "toleration_seconds" .tolerationSeconds -}}{{- end -}}
{{- $tolerations = append $tolerations $toleration -}}
{{- end -}}
{{- $_ := set $settings "tolerations" $tolerations -}}
{{- end -}}
{{- toYaml $settings -}}
{{- end -}}
