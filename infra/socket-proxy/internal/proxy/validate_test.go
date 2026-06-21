package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/imageallow"
	"github.com/stretchr/testify/require"
)

func loadAllowAllImages(t *testing.T) *imageallow.Allowlist {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/allow.txt"
	require.NoError(t, writeFileImpl(path, "ghcr.io/test/runner@sha256:ff\n"))
	a, err := imageallow.Load(path)
	require.NoError(t, err)
	return a
}

// minimalValidBody returns a JSON containers/create body that passes every
// refuse rule. Tests start from this and mutate one field at a time.
func minimalValidBody() map[string]any {
	return map[string]any{
		"Image": "ghcr.io/test/runner@sha256:ff",
		"User":  "1001:0",
		"HostConfig": map[string]any{
			"Privileged":  false,
			"CapAdd":      []any{},
			"CapDrop":     []any{"ALL"},
			"Devices":     []any{},
			"PidMode":     "",
			"NetworkMode": "rs-net-test",
			"IpcMode":     "",
			"UTSMode":     "",
			"UsernsMode":  "",
			"Sysctls":     map[string]any{},
			"SecurityOpt": []any{"no-new-privileges:true"},
			"Binds":       []any{},
		},
	}
}

// allowAll is an alias for loadAllowAllImages, used by egress-gate tests for
// readability consistency with the brief's test skeleton.
func allowAll(t *testing.T) *imageallow.Allowlist {
	t.Helper()
	return loadAllowAllImages(t)
}

func validate(t *testing.T, body map[string]any) error {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	// egressNet="" and egressVol="" keep both gates inert for existing tests.
	return ValidateContainerCreate(b, loadAllowAllImages(t), "", "")
}

// TestValidateContainerCreate_EgressAttach covers the egress-network gate:
//
//   - role=proxy attaching the egress network → allowed
//   - role=runner attaching the egress network → DENIED (isolation bypass)
//   - unlabeled container attaching the egress network → DENIED
//   - egressNet="" → gate is inert regardless of NetworkingConfig
//   - attach a different network → unaffected (not denied by the egress gate)
func TestValidateContainerCreate_EgressAttach(t *testing.T) {
	// mk builds a minimal valid body that attaches the given network via
	// NetworkingConfig.EndpointsConfig and carries the given role label.
	mk := func(role string) []byte {
		return []byte(`{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001:0",` +
			`"Labels":{"runsecure.role":"` + role + `"},` +
			`"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"]},` +
			`"NetworkingConfig":{"EndpointsConfig":{"spawn-egress":{}}}}`)
	}

	// Positive: proxy container is allowed to attach the egress network.
	if err := ValidateContainerCreate(mk("proxy"), allowAll(t), "spawn-egress", ""); err != nil {
		t.Fatalf("proxy->egress should be allowed: %v", err)
	}

	// Attacker: runner role must be denied.
	if err := ValidateContainerCreate(mk("runner"), allowAll(t), "spawn-egress", ""); err == nil {
		t.Fatal("SECURITY: runner->egress must be denied")
	}

	// Attacker: unlabeled container must be denied.
	if err := ValidateContainerCreate(mk(""), allowAll(t), "spawn-egress", ""); err == nil {
		t.Fatal("SECURITY: unlabeled->egress must be denied")
	}
}

// TestValidateContainerCreate_EgressGateInertWhenNetEmpty verifies that when
// RUNSECURE_EGRESS_NETWORK is not configured (empty string) the gate adds no
// new denials.
func TestValidateContainerCreate_EgressGateInertWhenNetEmpty(t *testing.T) {
	body := []byte(`{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001:0",` +
		`"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"]},` +
		`"NetworkingConfig":{"EndpointsConfig":{"spawn-egress":{}}}}`)
	// With egressNet="" the gate must not fire even if spawn-egress is attached.
	require.NoError(t, ValidateContainerCreate(body, allowAll(t), "", ""))
}

// TestValidateContainerCreate_NonEgressNetworkUnaffected verifies that
// attaching a network other than the egress network is not gated.
func TestValidateContainerCreate_NonEgressNetworkUnaffected(t *testing.T) {
	body := []byte(`{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001:0",` +
		`"Labels":{"runsecure.role":"runner"},` +
		`"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"]},` +
		`"NetworkingConfig":{"EndpointsConfig":{"rs-internal":{}}}}`)
	// runner attaches rs-internal, not spawn-egress → no egress-gate denial.
	require.NoError(t, ValidateContainerCreate(body, allowAll(t), "spawn-egress", ""))
}

// TestValidateContainerCreate_EgressAttach_ErrorSentinel verifies that the
// denial for runner->egress returns ErrEgressAttachDenied specifically.
func TestValidateContainerCreate_EgressAttach_ErrorSentinel(t *testing.T) {
	body := []byte(`{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001:0",` +
		`"Labels":{"runsecure.role":"runner"},` +
		`"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"]},` +
		`"NetworkingConfig":{"EndpointsConfig":{"spawn-egress":{}}}}`)
	err := ValidateContainerCreate(body, allowAll(t), "spawn-egress", "")
	require.ErrorIs(t, err, ErrEgressAttachDenied)
}

// TestValidateContainerCreate_EgressVolume covers the egress-volume bind gate.
// A volume-name bind source (no leading "/") may only be mounted by the
// designated egress volume on a runsecure.role=proxy container. Every other
// combination — runner role, a different volume name, or an unset egressVol —
// must be denied with ErrEgressVolumeDenied.
func TestValidateContainerCreate_EgressVolume(t *testing.T) {
	mk := func(role, bind string) []byte {
		return []byte(`{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001:0",` +
			`"Labels":{"runsecure.role":"` + role + `"},` +
			`"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"],` +
			`"Binds":["` + bind + `"]}}`)
	}

	t.Run("proxy+egressVol allowed", func(t *testing.T) {
		err := ValidateContainerCreate(
			mk("proxy", "myscope-egress-configs:/mnt/e:ro"),
			allowAll(t), "", "myscope-egress-configs")
		require.NoError(t, err)
	})

	t.Run("runner+egressVol DENIED", func(t *testing.T) {
		err := ValidateContainerCreate(
			mk("runner", "myscope-egress-configs:/mnt/e:ro"),
			allowAll(t), "", "myscope-egress-configs")
		require.ErrorIs(t, err, ErrEgressVolumeDenied)
	})

	t.Run("proxy+other volume DENIED", func(t *testing.T) {
		err := ValidateContainerCreate(
			mk("proxy", "other-volume:/mnt/e:ro"),
			allowAll(t), "", "myscope-egress-configs")
		require.ErrorIs(t, err, ErrEgressVolumeDenied)
	})

	t.Run("egressVol empty -> any volume name denied", func(t *testing.T) {
		err := ValidateContainerCreate(
			mk("proxy", "any-volume:/mnt/e:ro"),
			allowAll(t), "", "")
		require.ErrorIs(t, err, ErrEgressVolumeDenied)
	})

	t.Run("host-bind denial intact", func(t *testing.T) {
		err := ValidateContainerCreate(
			mk("proxy", "/var/run:/foo:ro"),
			allowAll(t), "", "vol")
		require.ErrorIs(t, err, ErrBindForbidden)
	})
}

func TestValidateContainerCreate_Baseline_OK(t *testing.T) {
	require.NoError(t, validate(t, minimalValidBody()))
}

func TestValidateContainerCreate_RefusesPrivileged(t *testing.T) {
	b := minimalValidBody()
	b["HostConfig"].(map[string]any)["Privileged"] = true
	require.ErrorIs(t, validate(t, b), ErrPrivilegedDenied)
}

func TestValidateContainerCreate_RefusesCapAdd(t *testing.T) {
	b := minimalValidBody()
	b["HostConfig"].(map[string]any)["CapAdd"] = []any{"NET_ADMIN"}
	require.ErrorIs(t, validate(t, b), ErrCapAddDenied)
}

func TestValidateContainerCreate_RefusesDevices(t *testing.T) {
	b := minimalValidBody()
	b["HostConfig"].(map[string]any)["Devices"] = []any{
		map[string]any{"PathOnHost": "/dev/kvm"},
	}
	require.ErrorIs(t, validate(t, b), ErrDevicesDenied)
}

func TestValidateContainerCreate_RefusesHostNamespaces(t *testing.T) {
	for _, tc := range []struct {
		field string
		want  error
	}{
		{"PidMode", ErrPidModeDenied},
		{"NetworkMode", ErrNetworkModeDenied},
		{"IpcMode", ErrIpcModeDenied},
		{"UTSMode", ErrUTSModeDenied},
		{"UsernsMode", ErrUsernsModeDenied},
	} {
		t.Run(tc.field, func(t *testing.T) {
			b := minimalValidBody()
			b["HostConfig"].(map[string]any)[tc.field] = "host"
			err := validate(t, b)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestValidateContainerCreate_RefusesNoneNetwork(t *testing.T) {
	b := minimalValidBody()
	b["HostConfig"].(map[string]any)["NetworkMode"] = "none"
	require.ErrorIs(t, validate(t, b), ErrNetworkModeDenied)
}

func TestValidateContainerCreate_RefusesSysctls(t *testing.T) {
	b := minimalValidBody()
	b["HostConfig"].(map[string]any)["Sysctls"] = map[string]any{"net.ipv4.ip_forward": "1"}
	require.ErrorIs(t, validate(t, b), ErrSysctlsDenied)
}

func TestValidateContainerCreate_RequiresNoNewPrivilegesSecOpt(t *testing.T) {
	b := minimalValidBody()
	b["HostConfig"].(map[string]any)["SecurityOpt"] = []any{}
	require.ErrorIs(t, validate(t, b), ErrSecurityOptMissingNoNewPrivs)
}

func TestValidateContainerCreate_RequiresCapDropALL(t *testing.T) {
	b := minimalValidBody()
	b["HostConfig"].(map[string]any)["CapDrop"] = []any{}
	require.ErrorIs(t, validate(t, b), ErrCapDropMissingALL)
}

func TestValidateContainerCreate_RefusesForbiddenBinds(t *testing.T) {
	for _, bind := range []string{
		"/var/run/docker.sock:/var/run/docker.sock",
		"/var/run/something:/x",
		"/var/lib/docker:/x",
		"/proc:/host/proc",
		"/sys:/host/sys",
		"/etc:/etc",
		"/root:/root",
		"/home/foo:/x",
		"/Users/naor:/x",
		"/some/weird/path/.ssh:/ssh", // suffix
		"/Users/x/.aws:/aws",         // suffix (also matched by /Users prefix)
		"/opt/state/.kube:/k",        // suffix-only
		"/private/.config/gh:/gh",    // suffix
		"/data/.docker:/dock",        // suffix
		"/secrets/.gnupg:/gpg",       // suffix
	} {
		t.Run(bind, func(t *testing.T) {
			b := minimalValidBody()
			b["HostConfig"].(map[string]any)["Binds"] = []any{bind}
			err := validate(t, b)
			require.ErrorIs(t, err, ErrBindForbidden)
		})
	}
}

func TestValidateContainerCreate_PermitsSafeBinds(t *testing.T) {
	for _, bind := range []string{
		"/tmp/orch-egress/spawn-x:/etc/squid:ro",
		"/var/folders/abc/T/runsecure/spawn-y:/etc/squid",
		"/opt/runsecure-data:/data",
	} {
		t.Run(bind, func(t *testing.T) {
			b := minimalValidBody()
			b["HostConfig"].(map[string]any)["Binds"] = []any{bind}
			// /var/folders is under /var/lib's prefix check? No — /var/lib only
			// matches /var/lib and /var/lib/*; /var/folders is unrelated.
			// But /var/run also matched as a prefix earlier — /var/folders is
			// fine because /var alone is NOT in the prefix list.
			require.NoError(t, validate(t, b))
		})
	}
}

func TestValidateContainerCreate_RefusesEmptyUser(t *testing.T) {
	b := minimalValidBody()
	b["User"] = ""
	require.ErrorIs(t, validate(t, b), ErrUserRequired)
}

func TestValidateContainerCreate_RefusesUntrustedImage(t *testing.T) {
	b := minimalValidBody()
	b["Image"] = "ghcr.io/test/runner:latest"
	require.ErrorIs(t, validate(t, b), ErrImageNotAllowed)

	b["Image"] = "ghcr.io/test/runner@sha256:other"
	require.ErrorIs(t, validate(t, b), ErrImageNotAllowed)
}

func TestValidateContainerCreate_RefusesMalformedJSON(t *testing.T) {
	err := ValidateContainerCreate([]byte("{ not json"), loadAllowAllImages(t), "", "")
	require.Error(t, err)
}

func TestValidateContainerCreate_BindsNonStringElements_Ignored(t *testing.T) {
	b := minimalValidBody()
	b["HostConfig"].(map[string]any)["Binds"] = []any{42, true}
	require.NoError(t, validate(t, b))
}

func TestValidateNetworkCreate_RequiresInternalBridge(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"Name":       "rs-net-test",
		"Driver":     "bridge",
		"Internal":   true,
		"Attachable": false,
	})
	require.NoError(t, ValidateNetworkCreate(body))

	bad, _ := json.Marshal(map[string]any{"Name": "x", "Driver": "host"})
	require.Error(t, ValidateNetworkCreate(bad))

	bad2, _ := json.Marshal(map[string]any{"Name": "x", "Driver": "bridge", "Internal": false})
	require.Error(t, ValidateNetworkCreate(bad2))

	bad3, _ := json.Marshal(map[string]any{"Name": "x", "Driver": "bridge", "Internal": true, "Attachable": true})
	require.Error(t, ValidateNetworkCreate(bad3))
}

func TestValidateNetworkCreate_RefusesMalformedJSON(t *testing.T) {
	require.Error(t, ValidateNetworkCreate([]byte("nope")))
}

// Belt-and-suspenders: confirm error strings include the rule context.
func TestErrors_AreDescriptive(t *testing.T) {
	require.NotEmpty(t, ErrPrivilegedDenied.Error())
	require.True(t, strings.Contains(ErrCapAddDenied.Error(), "CapAdd"))
}

// TestValidateContainerCreate_EgressAttach_NetworkMode covers Bypass 1:
// Docker also attaches a named network via HostConfig.NetworkMode="<network>".
// A body with role=runner + NetworkMode=egressNet (and NO EndpointsConfig)
// must be DENIED; role=proxy + NetworkMode=egressNet must be allowed.
func TestValidateContainerCreate_EgressAttach_NetworkMode(t *testing.T) {
	// mk builds a body using HostConfig.NetworkMode instead of EndpointsConfig.
	mk := func(role string) []byte {
		return []byte(`{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001:0",` +
			`"Labels":{"runsecure.role":"` + role + `"},` +
			`"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"],"NetworkMode":"spawn-egress"}}`)
	}

	// Attacker: runner role with NetworkMode=egressNet must be denied.
	err := ValidateContainerCreate(mk("runner"), allowAll(t), "spawn-egress", "")
	if err == nil {
		t.Fatal("SECURITY BYPASS: runner+NetworkMode=egressNet must be denied")
	}
	require.ErrorIs(t, err, ErrEgressAttachDenied)

	// Unlabeled container with NetworkMode=egressNet must also be denied.
	err = ValidateContainerCreate(mk(""), allowAll(t), "spawn-egress", "")
	if err == nil {
		t.Fatal("SECURITY BYPASS: unlabeled+NetworkMode=egressNet must be denied")
	}
	require.ErrorIs(t, err, ErrEgressAttachDenied)

	// Positive: proxy role with NetworkMode=egressNet is allowed.
	require.NoError(t, ValidateContainerCreate(mk("proxy"), allowAll(t), "spawn-egress", ""))
}

// TestValidateContainerCreate_EgressAttach_NetworkMode_Inert verifies that the
// NetworkMode gate does not fire when egressNet is empty.
func TestValidateContainerCreate_EgressAttach_NetworkMode_Inert(t *testing.T) {
	body := []byte(`{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001:0",` +
		`"Labels":{"runsecure.role":"runner"},` +
		`"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"],"NetworkMode":"spawn-egress"}}`)
	// With egressNet="" the NetworkMode gate must not fire.
	require.NoError(t, ValidateContainerCreate(body, allowAll(t), "", ""))
}

func TestContainsString_NilSlice(t *testing.T) {
	require.False(t, containsString(nil, "x"))
	require.False(t, containsString(map[string]any{}, "x"))
	require.False(t, containsString([]any{42}, "x")) // non-string element
}

func TestCheckBinds_NilInput(t *testing.T) {
	require.NoError(t, checkBinds(nil))
	require.NoError(t, checkBinds("not-a-slice"))
}
