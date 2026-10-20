{{/*
Expand the name of the chart.
*/}}
{{- define "kresheen.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kresheen.fullname" -}}
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
{{- define "kresheen.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kresheen.labels" -}}
helm.sh/chart: {{ include "kresheen.chart" . }}
{{ include "kresheen.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kresheen.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kresheen.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Bundled dev Postgres hostname (the Service this chart creates when
postgresql.enabled is true).
*/}}
{{- define "kresheen.postgresHost" -}}
{{- printf "%s-postgres" (include "kresheen.fullname" .) }}
{{- end }}

{{/*
The database URL the app connects with: bundled dev Postgres, or the
user-supplied external one.
*/}}
{{- define "kresheen.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql+psycopg://%s:%s@%s:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "kresheen.postgresHost" .) .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.postgresql.externalDatabaseUrl }}
{{- end }}
{{- end }}

{{/*
Container image: repository@digest when image.digest is set, otherwise repository:tag (tag defaults to the chart appVersion).
*/}}
{{- define "kresheen.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end }}
