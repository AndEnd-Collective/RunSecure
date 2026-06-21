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
Orchestrator image reference (repository@digest).
Using digest when it is a real SHA (not the placeholder zeros).
In production deployments the digest overrides the tag.
*/}}
{{- define "runsecure-orchestrator.image" -}}
{{- $img := .Values.image.orchestrator }}
{{- printf "%s@%s" $img.repository $img.digest }}
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
