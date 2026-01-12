{{/*
Expand the name of the chart.
*/}}
{{- define "trix.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "trix.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "trix.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "trix.labels" -}}
helm.sh/chart: {{ include "trix.chart" . }}
{{ include "trix.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "trix.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "trix.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "trix.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL fullname
*/}}
{{- define "trix.postgresql.fullname" -}}
{{- printf "%s-db" (include "trix.fullname" .) }}
{{- end }}

{{/*
PostgreSQL host
*/}}
{{- define "trix.postgresql.host" -}}
{{- if .Values.postgresql.enabled }}
{{- include "trix.postgresql.fullname" . }}
{{- else }}
{{- .Values.postgresql.external.host }}
{{- end }}
{{- end }}

{{/*
PostgreSQL port
*/}}
{{- define "trix.postgresql.port" -}}
{{- if .Values.postgresql.enabled }}
{{- 5432 }}
{{- else }}
{{- .Values.postgresql.external.port }}
{{- end }}
{{- end }}

{{/*
PostgreSQL database
*/}}
{{- define "trix.postgresql.database" -}}
{{- if .Values.postgresql.enabled }}
{{- .Values.postgresql.database }}
{{- else }}
{{- .Values.postgresql.external.database }}
{{- end }}
{{- end }}

{{/*
PostgreSQL secret name
*/}}
{{- define "trix.postgresql.secretName" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-credentials" (include "trix.fullname" .) }}
{{- else if .Values.postgresql.external.existingSecret }}
{{- .Values.postgresql.external.existingSecret }}
{{- else }}
{{- printf "%s-credentials" (include "trix.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Database URL
*/}}
{{- define "trix.databaseUrl" -}}
{{- $host := include "trix.postgresql.host" . }}
{{- $port := include "trix.postgresql.port" . }}
{{- $database := include "trix.postgresql.database" . }}
{{- $sslMode := .Values.postgresql.external.sslMode | default "disable" }}
{{- printf "postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@%s:%s/%s?sslmode=%s" $host (toString $port) $database $sslMode }}
{{- end }}
