{{- define "helixiam.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "helixiam.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "helixiam.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "helixiam.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: helixiam
{{- end -}}

{{- define "helixiam.selectorLabels" -}}
app.kubernetes.io/name: {{ include "helixiam.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "helixiam.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "helixiam.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "helixiam.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/*
Whether the release needs Redis: the Redis HTTP-session store or the Redis token store (item 5). Fails on a store
name the server does not know. Renders "true" or "".
*/}}
{{- define "helixiam.redisRequired" -}}
{{- $session := .Values.config.sessionStore | default "redis" -}}
{{- $token := .Values.config.tokenStore | default "queue" -}}
{{- if not (has $session (list "redis" "queue")) -}}
{{- fail (printf "helixiam: config.sessionStore must be redis or queue (got %q)" $session) -}}
{{- end -}}
{{- if not (has $token (list "queue" "redis")) -}}
{{- fail (printf "helixiam: config.tokenStore must be queue or redis (got %q)" $token) -}}
{{- end -}}
{{- if or (eq $session "redis") (eq $token "redis") -}}true{{- end -}}
{{- end -}}

{{/* Whether the pod connects to Redis: it is required, or a host is configured anyway. Renders "true" or "". */}}
{{- define "helixiam.redisUsed" -}}
{{- if or (include "helixiam.redisRequired" .) .Values.redis.host -}}true{{- end -}}
{{- end -}}

{{/* Fail fast on required values so a bad install is caught at render time. */}}
{{- define "helixiam.require" -}}
{{- if not .val -}}
{{- fail (printf "helixiam: %s is required" .name) -}}
{{- end -}}
{{- end -}}
