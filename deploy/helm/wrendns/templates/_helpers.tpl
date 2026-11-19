{{- define "wrendns.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wrendns.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains (include "wrendns.name" .) .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "wrendns.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "wrendns.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "wrendns.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "wrendns.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wrendns.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: all
{{- end }}

{{/* The DNS port inside the pod: 53 on the host network, else dnsPort. */}}
{{- define "wrendns.dnsPort" -}}
{{- if .Values.hostNetwork }}53{{ else }}{{ .Values.dnsPort }}{{ end }}
{{- end }}

{{/* REQ: DNS-002/003 — encrypted DNS is on, and the TLS Secret that serves it. */}}
{{- define "wrendns.encrypted" -}}
{{- if or .Values.encrypted.dot.enabled .Values.encrypted.doh.enabled .Values.encrypted.doq.enabled }}true{{ end }}
{{- end }}
{{- define "wrendns.tlsSecret" -}}
{{- if .Values.encrypted.tls.certManager.enabled }}{{ include "wrendns.fullname" . }}-dns-tls{{ else }}{{ .Values.encrypted.tls.secretName }}{{ end }}
{{- end }}
{{/* Ports inside the pod: the Service port on the host network, else an unprivileged one. */}}
{{- define "wrendns.dotPort" -}}
{{- if .Values.hostNetwork }}{{ .Values.encrypted.dot.port }}{{ else }}8853{{ end }}
{{- end }}
{{- define "wrendns.dohPort" -}}
{{- if .Values.hostNetwork }}{{ .Values.encrypted.doh.port }}{{ else }}8443{{ end }}
{{- end }}
{{- define "wrendns.doqPort" -}}
{{- if .Values.hostNetwork }}{{ .Values.encrypted.doq.port }}{{ else }}8853{{ end }}
{{- end }}

{{/* REQ: CLU-009 — mode: scaled. */}}
{{- define "wrendns.scaled" -}}
{{- if eq .Values.mode "scaled" }}true{{ end }}
{{- end }}
{{/* Every WrenDNS pod of this release (DNS goes to all of them in scaled mode). */}}
{{- define "wrendns.podLabels" -}}
app.kubernetes.io/name: {{ include "wrendns.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "wrendns.resolverLabels" -}}
{{ include "wrendns.podLabels" . }}
app.kubernetes.io/component: resolver
{{- end }}
{{- define "wrendns.clusterSecret" -}}
{{- .Values.cluster.bootstrapSecret.existingSecret | default (printf "%s-cluster" (include "wrendns.fullname" .)) }}
{{- end }}
{{/* REQ: OPS-014 (ADR-903 §3) — the Secret holding the secrets store's key, mounted on the
controller (or allInOne pod) only: `secretsKey.existingSecret`, the chart's own with
`secretsKey.generate`, or nothing (the key is made in the data directory). */}}
{{- define "wrendns.secretsKeySecret" -}}
{{- if .Values.secretsKey.existingSecret }}
{{- .Values.secretsKey.existingSecret }}
{{- else if .Values.secretsKey.generate }}
{{- printf "%s-secrets-key" (include "wrendns.fullname" .) }}
{{- end }}
{{- end }}
{{/* REQ: FLT-017 — the ServiceAccount the controller (or allInOne pod) uses to watch pods. */}}
{{- define "wrendns.serviceAccountName" -}}
{{- .Values.kubernetes.rbac.serviceAccountName | default (printf "%s-workloads" (include "wrendns.fullname" .)) }}
{{- end }}
{{/* REQ: FLT-017 — an IPv4 CIDR's reverse zone, rounded to whole octets (10.42.0.0/16 →
42.10.in-addr.arpa). Empty for anything else. */}}
{{- define "wrendns.reverseZone" -}}
{{- $parts := splitList "/" . }}
{{- if eq (len $parts) 2 }}
{{- $octets := splitList "." (index $parts 0) }}
{{- $keep := div (atoi (index $parts 1)) 8 }}
{{- if and (eq (len $octets) 4) (gt $keep 0) }}
{{- $rev := list }}
{{- range $i := until (int $keep) }}{{ $rev = prepend $rev (index $octets $i) }}{{ end }}
{{- printf "%s.in-addr.arpa" (join "." $rev) }}
{{- end }}
{{- end }}
{{- end }}
{{/* REQ: FLT-017 — WrenDNS's own pods ask CoreDNS, not their own Service: with the
kubelet's cluster DNS pointed at WrenDNS, they'd otherwise start by asking themselves. */}}
{{- define "wrendns.podDns" -}}
{{- if and .Values.kubernetes.enabled .Values.kubernetes.ownPodsUseClusterDns }}
dnsPolicy: None
dnsConfig:
  nameservers: [{{ .Values.kubernetes.clusterDns | quote }}]
  searches:
    - {{ printf "%s.svc.%s" .Release.Namespace .Values.kubernetes.clusterDomain }}
    - {{ printf "svc.%s" .Values.kubernetes.clusterDomain }}
    - {{ .Values.kubernetes.clusterDomain }}
  options: [{ name: ndots, value: "5" }]
{{- else if .Values.hostNetwork }}
dnsPolicy: ClusterFirstWithHostNet
{{- end }}
{{- end }}
{{/* The controller's in-cluster cluster URL (what resolver pods join). */}}
{{- define "wrendns.clusterURL" -}}
https://{{ include "wrendns.fullname" . }}-cluster.{{ .Release.Namespace }}.svc:{{ .Values.cluster.port }}
{{- end }}
