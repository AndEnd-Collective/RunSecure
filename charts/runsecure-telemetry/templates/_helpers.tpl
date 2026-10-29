{{- define "telemetry.gatewayImage" -}}
{{- printf "%s@%s" .Values.gateway.image.repository .Values.gateway.image.digest -}}
{{- end -}}
{{- define "telemetry.nodeImage" -}}
{{- printf "%s@%s" .Values.nodeReader.image.repository .Values.nodeReader.image.digest -}}
{{- end -}}
{{- define "telemetry.validate" -}}
{{- if .Values.enabled -}}
{{- if not (regexMatch "^[0-9]{12}$" .Values.aws.accountId) -}}{{ fail "aws.accountId must be the reviewed AWS account ID" }}{{- end -}}
{{- range $role, $image := dict "gateway" .Values.gateway.image "nodeReader" .Values.nodeReader.image -}}
{{- if not (regexMatch "^[a-zA-Z0-9][a-zA-Z0-9./:_-]+$" $image.repository) -}}{{ fail (printf "%s.image.repository is required" $role) }}{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $image.digest) -}}{{ fail (printf "%s.image.digest must be an independently read-back manifest digest" $role) }}{{- end -}}
{{- end -}}
{{- if eq .Values.gateway.image.digest .Values.nodeReader.image.digest -}}{{ fail "gateway.image and nodeReader.image must identify distinct role images" }}{{- end -}}
{{- range $key, $value := dict "clusterName" .Values.clusterName "aws.region" .Values.aws.region "aws.logGroup" .Values.aws.logGroup "tls.gatewaySecret" .Values.tls.gatewaySecret "tls.agentSecret" .Values.tls.agentSecret "gateway.storageClassName" .Values.gateway.storageClassName -}}
{{- if not $value -}}{{ fail (printf "%s is required" $key) }}{{- end -}}
{{- end -}}
{{- if not (regexMatch "^/runsecure/[a-z0-9-]+/telemetry$" .Values.aws.logGroup) -}}{{ fail "aws.logGroup must be fixed /runsecure/<name>/telemetry" }}{{- end -}}
{{- if not (regexMatch "^[a-zA-Z0-9][a-zA-Z0-9_-]{0,80}$" .Values.aws.logStreamPrefix) -}}{{ fail "aws.logStreamPrefix must be fixed and contain no resource placeholders" }}{{- end -}}
{{- if not (has .Values.environment (list "Development" "Testing" "Staging" "Production")) -}}{{ fail "environment must be a canonical title-case value" }}{{- end -}}
{{- if not .Values.aws.logsEndpointIPs -}}{{ fail "aws.logsEndpointIPs must contain exact private Logs endpoint IPv4 /32s" }}{{- end -}}
{{- if not .Values.dns.serviceCIDRs -}}{{ fail "dns.serviceCIDRs must contain exact cluster DNS IPv4 /32s" }}{{- end -}}
{{- range concat .Values.aws.logsEndpointIPs .Values.dns.serviceCIDRs -}}
{{- if not (regexMatch "^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$" .) -}}{{ fail "endpoint/DNS CIDRs must be exact private IPv4 /32s" }}{{- end -}}
{{- if not (or (hasPrefix "10." .) (hasPrefix "192.168." .) (regexMatch "^172\\.(1[6-9]|2[0-9]|3[01])\\." .)) -}}{{ fail "endpoint/DNS CIDRs must be private IPv4 /32s" }}{{- end -}}
{{- range splitList "." (trimSuffix "/32" .) -}}{{- if gt (int .) 255 -}}{{ fail "invalid IPv4 octet" }}{{- end -}}{{- end -}}
{{- end -}}
{{- if not .Values.trustedSources -}}{{ fail "trustedSources requires reviewed controller origin entries" }}{{- end -}}
{{- range .Values.trustedSources -}}
{{- if or (not (regexMatch "^runsecure-[a-z0-9-]+$" .namespace)) (not (has .container (list "orchestrator" "socket-proxy"))) (not (regexMatch "^[a-z0-9-]+-$" .podNamePrefix)) -}}{{ fail "trustedSources require management namespace, controller container and explicit pod prefix" }}{{- end -}}
{{- if not (or (and (eq .container "orchestrator") (eq .signature "runsecure-orchestrator-v1")) (and (eq .container "socket-proxy") (eq .signature "runsecure-socket-proxy-v1"))) -}}{{ fail "trusted source signature must match the selected controller type" }}{{- end -}}
{{- end -}}
{{- if not (has .Values.nodeReader.journalDirectory (list "/var/log/journal" "/run/log/journal")) -}}{{ fail "journalDirectory must select a mounted system journal directory" }}{{- end -}}
{{- if or (not .Values.nodeReader.installGuardOnly) .Values.nodeReader.activateGuardNamespace -}}
{{- if not .Values.renderOnly -}}
{{- $expected := include "telemetry.guard" . | fromYaml -}}
{{- $live := lookup "admissionregistration.k8s.io/v1" "ValidatingAdmissionPolicy" "" "runsecure-telemetry-node-reader" -}}
{{- $binding := lookup "admissionregistration.k8s.io/v1" "ValidatingAdmissionPolicyBinding" "" "runsecure-telemetry-node-reader" -}}
{{- $expectedBinding := include "telemetry.guardBinding" . | fromYaml -}}
{{- if or (not $live) (not $binding) -}}{{ fail "installGuardOnly first; exact admission policy/binding live readback required (offline render: renderOnly=true emits disabled fixtures)" }}{{- end -}}
{{- if or (ne $live.spec.failurePolicy "Fail") (ne (toJson $live.spec.validations) (toJson $expected.spec.validations)) (ne (toJson $live.spec.matchConditions) (toJson $expected.spec.matchConditions)) (ne (toJson $live.spec.matchConstraints.resourceRules) (toJson $expected.spec.matchConstraints.resourceRules)) (ne $binding.spec.policyName $expectedBinding.spec.policyName) (ne (toJson $binding.spec.validationActions) (toJson $expectedBinding.spec.validationActions)) (hasKey $binding.spec "matchResources") (hasKey $live.spec "paramKind") -}}{{ fail "live admission policy/binding differs from the required guard" }}{{- end -}}
{{- if or (gt (len ($live.spec.matchConstraints.namespaceSelector | default dict)) 0) (gt (len ($live.spec.matchConstraints.objectSelector | default dict)) 0) (gt (len ($live.spec.matchConstraints.excludeResourceRules | default list)) 0) (hasKey $binding.spec "paramRef") -}}{{ fail "admission guard must have no match exclusions or parameter bypass" }}{{- end -}}
{{- if or (not $live.status) (ne (toString $live.status.observedGeneration) (toString $live.metadata.generation)) (not (hasKey $live.status "typeChecking")) (gt (len ($live.status.typeChecking.expressionWarnings | default list)) 0) -}}{{ fail "admission guard must observe current generation and complete CEL type checking without warnings" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "telemetry.guard" -}}
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: runsecure-telemetry-node-reader
spec:
  failurePolicy: Fail
  matchConstraints:
    matchPolicy: Equivalent
    resourceRules:
      - apiGroups: [""]
        apiVersions: [v1]
        operations: [CREATE, UPDATE]
        resources: [pods, pods/ephemeralcontainers]
        scope: Namespaced
  matchConditions:
    - name: fixed-node-namespace
      expression: request.namespace == 'runsecure-observability-node'
  validations:
    - expression: >-
        object.spec.serviceAccountName == 'runsecure-telemetry-node' &&
        has(object.spec.automountServiceAccountToken) && !object.spec.automountServiceAccountToken &&
        (!has(object.spec.hostNetwork) || !object.spec.hostNetwork) &&
        (!has(object.spec.hostPID) || !object.spec.hostPID) &&
        (!has(object.spec.hostIPC) || !object.spec.hostIPC) &&
        (!has(object.spec.initContainers) || size(object.spec.initContainers) == 0) &&
        (!has(object.spec.ephemeralContainers) || size(object.spec.ephemeralContainers) == 0) &&
        size(object.spec.containers) == 1 && object.spec.containers[0].name == 'collector' &&
        object.spec.containers[0].image == '{{ include "telemetry.nodeImage" . }}' &&
        object.spec.containers[0].command == ['/usr/local/bin/runsecure-collector'] &&
        object.spec.containers[0].args == ['--config=/etc/otel/config.yaml'] &&
        (!has(object.spec.containers[0].envFrom) || size(object.spec.containers[0].envFrom) == 0) &&
        (!has(object.spec.containers[0].lifecycle)) &&
        size(object.spec.containers[0].env) == 2 && object.spec.containers[0].env.all(e,
          (e.name == 'NODE_NAME' && has(e.valueFrom) && has(e.valueFrom.fieldRef) && e.valueFrom.fieldRef.fieldPath == 'spec.nodeName') ||
          (e.name == 'AWS_EC2_METADATA_DISABLED' && e.value == 'true'))
      message: Only the exact approved single-container telemetry reader is allowed; host namespaces and injected containers are forbidden
    - expression: >-
        object.spec.containers.all(c,
          has(c.securityContext) && has(c.securityContext.privileged) && !c.securityContext.privileged &&
          has(c.securityContext.allowPrivilegeEscalation) && !c.securityContext.allowPrivilegeEscalation &&
          has(c.securityContext.readOnlyRootFilesystem) && c.securityContext.readOnlyRootFilesystem &&
          has(c.securityContext.capabilities) && c.securityContext.capabilities.drop == ['ALL'] &&
          (!has(c.securityContext.capabilities.add) || size(c.securityContext.capabilities.add) == 0) &&
          has(c.securityContext.seccompProfile) && c.securityContext.seccompProfile.type == 'RuntimeDefault')
      message: Reader must have no privilege escalation or capabilities and use read-only rootfs plus RuntimeDefault seccomp
    - expression: >-
        size(object.spec.volumes) == 8 && object.spec.volumes.all(v,
          (v.name == 'pod-logs' && has(v.hostPath) && v.hostPath.path == '/var/log/pods' && v.hostPath.type == 'Directory') ||
          (v.name == 'journals' && has(v.hostPath) && v.hostPath.path == '/var/log/journal' && v.hostPath.type == 'DirectoryOrCreate') ||
          (v.name == 'run-journals' && has(v.hostPath) && v.hostPath.path == '/run/log/journal' && v.hostPath.type == 'DirectoryOrCreate') ||
          (v.name == 'cni-logs' && has(v.hostPath) && v.hostPath.path == '/var/log/aws-routed-eni' && v.hostPath.type == 'DirectoryOrCreate') ||
          (v.name == 'state' && has(v.hostPath) && v.hostPath.path == '/var/lib/runsecure-telemetry' && v.hostPath.type == 'DirectoryOrCreate') ||
          (v.name == 'config' && has(v.configMap) && v.configMap.name == 'runsecure-telemetry-node') ||
          (v.name == 'tls' && has(v.secret) && v.secret.secretName == '{{ .Values.tls.agentSecret }}') ||
          (v.name == 'tmp' && has(v.emptyDir) && v.emptyDir.medium == 'Memory'))
      message: Only the bounded log directories, collector state and exact configuration/TLS volumes are allowed
    - expression: >-
        object.spec.containers.all(c, size(c.volumeMounts) == 8 && c.volumeMounts.all(m,
          !has(m.subPath) && !has(m.subPathExpr) && !has(m.mountPropagation) && (
          (m.name == 'pod-logs' && m.mountPath == '/var/log/pods' && has(m.readOnly) && m.readOnly) ||
          (m.name == 'journals' && m.mountPath == '/var/log/journal' && has(m.readOnly) && m.readOnly) ||
          (m.name == 'run-journals' && m.mountPath == '/run/log/journal' && has(m.readOnly) && m.readOnly) ||
          (m.name == 'cni-logs' && m.mountPath == '/var/log/aws-routed-eni' && has(m.readOnly) && m.readOnly) ||
          (m.name == 'state' && m.mountPath == '/var/lib/otel') ||
          (m.name == 'config' && m.mountPath == '/etc/otel' && has(m.readOnly) && m.readOnly) ||
          (m.name == 'tls' && m.mountPath == '/etc/otel-tls' && has(m.readOnly) && m.readOnly) ||
          (m.name == 'tmp' && m.mountPath == '/tmp'))))
      message: All host logs must be read-only; writable mounts are limited to collector state and tmpfs
{{- end -}}
{{- define "telemetry.guardBinding" -}}
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: runsecure-telemetry-node-reader
spec:
  policyName: runsecure-telemetry-node-reader
  validationActions: [Deny]
{{- end -}}
