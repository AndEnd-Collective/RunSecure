package admissiontests

import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"testing"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
)

func chartGuard(t *testing.T) ([]cel.Program, map[string]any) {
	t.Helper()
	out, err := exec.Command("helm", "template", "telemetry", "../../../../charts/runsecure-telemetry", "-f", "../values.render.yaml").CombinedOutput()
	if err != nil {
		t.Fatalf("helm render: %v: %s", err, out)
	}
	var policy, daemon map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch doc["kind"] {
		case "ValidatingAdmissionPolicy":
			policy = doc
		case "DaemonSet":
			daemon = doc
		}
	}
	if policy == nil || daemon == nil {
		t.Fatal("missing guard/daemon")
	}
	env, err := cel.NewEnv(cel.Variable("object", cel.DynType), cel.Variable("request", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	spec := policy["spec"].(map[string]any)
	var programs []cel.Program
	for _, raw := range spec["validations"].([]any) {
		expression := raw.(map[string]any)["expression"].(string)
		ast, issues := env.Compile(expression)
		if issues.Err() != nil {
			t.Fatalf("CEL compile: %v\n%s", issues.Err(), expression)
		}
		program, err := env.Program(ast)
		if err != nil {
			t.Fatal(err)
		}
		programs = append(programs, program)
	}
	template := daemon["spec"].(map[string]any)["template"].(map[string]any)
	podSpec := template["spec"].(map[string]any)
	delete(podSpec, "initContainers") // remove render-only commissioning blocker
	delete(podSpec["nodeSelector"].(map[string]any), "runsecure.io/telemetry-render-only")
	return programs, map[string]any{"spec": podSpec}
}

func clone(in map[string]any) map[string]any {
	b, _ := json.Marshal(in)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}
func spec(p map[string]any) map[string]any { return p["spec"].(map[string]any) }
func container(p map[string]any) map[string]any {
	return spec(p)["containers"].([]any)[0].(map[string]any)
}

func TestGuardPermitsExactReaderAndDeniesEscapes(t *testing.T) {
	programs, valid := chartGuard(t)
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"privileged", func(p map[string]any) { container(p)["securityContext"].(map[string]any)["privileged"] = true }},
		{"host-network", func(p map[string]any) { spec(p)["hostNetwork"] = true }},
		{"host-pid", func(p map[string]any) { spec(p)["hostPID"] = true }},
		{"host-ipc", func(p map[string]any) { spec(p)["hostIPC"] = true }},
		{"token", func(p map[string]any) { spec(p)["automountServiceAccountToken"] = true }},
		{"image", func(p map[string]any) { container(p)["image"] = "attacker.invalid/image@sha256:bbbb" }},
		{"command", func(p map[string]any) { container(p)["command"] = []any{"/bin/sh"} }},
		{"args", func(p map[string]any) { container(p)["args"] = []any{"--config=env:MALICIOUS"} }},
		{"env", func(p map[string]any) {
			container(p)["env"] = append(container(p)["env"].([]any), map[string]any{"name": "MALICIOUS", "value": "data"})
		}},
		{"root-hostpath", func(p map[string]any) {
			spec(p)["volumes"].([]any)[0].(map[string]any)["hostPath"].(map[string]any)["path"] = "/"
		}},
		{"docker-socket", func(p map[string]any) {
			spec(p)["volumes"].([]any)[0].(map[string]any)["hostPath"].(map[string]any)["path"] = "/var/run/docker.sock"
		}},
		{"writable-logs", func(p map[string]any) { container(p)["volumeMounts"].([]any)[0].(map[string]any)["readOnly"] = false }},
		{"subpath", func(p map[string]any) {
			container(p)["volumeMounts"].([]any)[0].(map[string]any)["subPath"] = "../../etc"
		}},
		{"bidirectional", func(p map[string]any) {
			container(p)["volumeMounts"].([]any)[0].(map[string]any)["mountPropagation"] = "Bidirectional"
		}},
		{"capability", func(p map[string]any) {
			container(p)["securityContext"].(map[string]any)["capabilities"].(map[string]any)["add"] = []any{"SYS_ADMIN"}
		}},
		{"init-container", func(p map[string]any) { spec(p)["initContainers"] = []any{clone(container(p))} }},
		{"ephemeral-container", func(p map[string]any) { spec(p)["ephemeralContainers"] = []any{clone(container(p))} }},
		{"sidecar", func(p map[string]any) {
			spec(p)["containers"] = append(spec(p)["containers"].([]any), clone(container(p)))
		}},
	}
	evaluate := func(p map[string]any) bool {
		for _, program := range programs {
			out, _, err := program.Eval(map[string]any{"object": p, "request": map[string]any{"namespace": "runsecure-observability-node"}})
			if err != nil || out.Value() != true {
				return false
			}
		}
		return true
	}
	if !evaluate(valid) {
		for i, program := range programs {
			out, _, err := program.Eval(map[string]any{"object": valid, "request": map[string]any{"namespace": "runsecure-observability-node"}})
			t.Logf("stage %d: %v %v", i, out, err)
		}
		t.Fatal("valid exact reader must pass")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := clone(valid)
			tc.change(p)
			if evaluate(p) {
				t.Fatal("unsafe reader accepted")
			}
		})
	}
}
