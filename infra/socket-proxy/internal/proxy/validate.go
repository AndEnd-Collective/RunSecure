package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/imageallow"
)

// Refuse-rule errors — exported so tests can assert via errors.Is and the
// proxy can map specific rule violations to structured 403 responses.
var (
	ErrPrivilegedDenied             = errors.New("HostConfig.Privileged=true denied")
	ErrCapAddDenied                 = errors.New("HostConfig.CapAdd non-empty denied")
	ErrCapDropMissingALL            = errors.New("HostConfig.CapDrop must include 'ALL'")
	ErrDevicesDenied                = errors.New("HostConfig.Devices non-empty denied")
	ErrPidModeDenied                = errors.New("HostConfig.PidMode=host denied")
	ErrNetworkModeDenied            = errors.New("HostConfig.NetworkMode 'host' or 'none' denied")
	ErrIpcModeDenied                = errors.New("HostConfig.IpcMode=host denied")
	ErrUTSModeDenied                = errors.New("HostConfig.UTSMode=host denied")
	ErrUsernsModeDenied             = errors.New("HostConfig.UsernsMode=host denied")
	ErrSysctlsDenied                = errors.New("HostConfig.Sysctls non-empty denied")
	ErrSecurityOptMissingNoNewPrivs = errors.New("HostConfig.SecurityOpt missing no-new-privileges:true")
	ErrBindForbidden                = errors.New("HostConfig.Binds contains a forbidden host path")
	ErrUserRequired                 = errors.New("User field is required and must be non-root")
	ErrImageNotAllowed              = errors.New("Image not in digest allowlist")
	// ErrEgressAttachDenied is returned when a container-create request attaches
	// the designated egress network without carrying the runsecure.role=proxy
	// label. This is the isolation-bypass gate: only the proxy sidecar may join
	// the outbound egress network; runner containers must never reach it.
	ErrEgressAttachDenied = errors.New("attachment to egress network requires runsecure.role=proxy")
	// ErrEgressVolumeDenied is returned when a container-create request mounts a
	// named Docker volume (a Bind source with no leading "/") that is not the
	// designated egress volume, or mounts the designated egress volume without
	// carrying runsecure.role=proxy. Only the proxy sidecar may mount the egress
	// configs volume; runner containers must never mount it.
	ErrEgressVolumeDenied = errors.New("volume mount requires runsecure.role=proxy and must be the designated egress volume")
)

// Forbidden host-path prefixes for HostConfig.Binds source paths.
//
// Covers:
//   - the docker socket itself (escape hatch)
//   - /proc, /sys (kernel state)
//   - /etc (host configuration)
//   - /root, /home, /Users (user homes — macOS uses /Users; Linux /home + /root)
//   - /var/run (docker socket variant), /var/lib (docker state, container runtimes)
var forbiddenBindPrefixes = []string{
	"/var/run/docker.sock",
	"/var/run",
	"/var/lib",
	"/proc",
	"/sys",
	"/etc",
	"/root",
	"/home",
	"/Users",
}

// Suffix-blocklist: any bind source path ending in one of these is refused,
// regardless of its prefix. Covers user-relative sensitive folders that
// could appear under arbitrary parents (e.g. ~/.ssh, ~/.aws, ~/.kube).
var forbiddenBindSuffixes = []string{
	"/.ssh",
	"/.aws",
	"/.kube",
	"/.config/gh",
	"/.docker",
	"/.gnupg",
}

// ValidateContainerCreate parses body as Docker's containers/create request
// and refuses it if any spec §7.2 rule fails.
//
// egressNet is the name of the designated egress network (read from
// RUNSECURE_EGRESS_NETWORK at server init). When non-empty, any request that
// attaches this network via NetworkingConfig.EndpointsConfig must carry
// Labels["runsecure.role"]="proxy"; all other values, including the empty
// string and "runner", are denied with ErrEgressAttachDenied. Pass "" to
// disable the egress gate (development / test environments without an egress
// network).
//
// egressVol is the name of the designated egress configs volume (read from
// RUNSECURE_EGRESS_VOLUME at server init). Any HostConfig.Binds entry whose
// source is a volume name (no leading "/") must be exactly egressVol AND the
// request must carry Labels["runsecure.role"]="proxy"; everything else is
// denied with ErrEgressVolumeDenied. Pass "" to deny ALL named-volume mounts
// (the gate is fail-closed: an unset egressVol means no volume may be mounted).
//
// The function does NOT modify the body; it only validates.
func ValidateContainerCreate(body []byte, images *imageallow.Allowlist, egressNet string, egressVol string) error {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("malformed JSON: %w", err)
	}

	image, _ := req["Image"].(string)
	if !images.Allows(image) {
		return ErrImageNotAllowed
	}

	user, _ := req["User"].(string)
	if user == "" {
		return ErrUserRequired
	}

	hc, _ := req["HostConfig"].(map[string]any)
	if hc == nil {
		hc = map[string]any{}
	}

	if priv, _ := hc["Privileged"].(bool); priv {
		return ErrPrivilegedDenied
	}
	if arr, ok := hc["CapAdd"].([]any); ok && len(arr) > 0 {
		return ErrCapAddDenied
	}
	if !containsString(hc["CapDrop"], "ALL") {
		return ErrCapDropMissingALL
	}
	if arr, ok := hc["Devices"].([]any); ok && len(arr) > 0 {
		return ErrDevicesDenied
	}
	if s, _ := hc["PidMode"].(string); s == "host" {
		return ErrPidModeDenied
	}
	if s, _ := hc["NetworkMode"].(string); s == "host" || s == "none" {
		return ErrNetworkModeDenied
	}
	if s, _ := hc["IpcMode"].(string); s == "host" {
		return ErrIpcModeDenied
	}
	if s, _ := hc["UTSMode"].(string); s == "host" {
		return ErrUTSModeDenied
	}
	if s, _ := hc["UsernsMode"].(string); s == "host" {
		return ErrUsernsModeDenied
	}
	if m, ok := hc["Sysctls"].(map[string]any); ok && len(m) > 0 {
		return ErrSysctlsDenied
	}
	if !containsString(hc["SecurityOpt"], "no-new-privileges:true") {
		return ErrSecurityOptMissingNoNewPrivs
	}
	if err := checkBinds(hc["Binds"]); err != nil {
		return err
	}

	// Egress-volume gate: any Bind whose source is a named volume (no leading
	// "/") may only be the designated egress volume on a role=proxy container.
	// checkBinds already cleared host-path Binds; this handles volume-name Binds
	// which it deliberately ignores (no leading "/" never matches a forbidden
	// prefix). Fail-closed: egressVol=="" denies every named-volume mount.
	{
		labels, _ := req["Labels"].(map[string]any)
		role, _ := labels["runsecure.role"].(string)
		if arr, ok := hc["Binds"].([]any); ok {
			for _, item := range arr {
				s, ok := item.(string)
				if !ok {
					continue
				}
				parts := strings.SplitN(s, ":", 3)
				src := parts[0]
				if strings.HasPrefix(src, "/") {
					continue // host path — already vetted by checkBinds
				}
				// Named-volume source: gate it.
				if egressVol == "" || src != egressVol || role != "proxy" {
					return ErrEgressVolumeDenied
				}
				// Mode check: must be explicitly ro.
				mode := ""
				if len(parts) == 3 {
					mode = parts[2]
				}
				if !strings.Contains(mode, "ro") {
					return ErrEgressVolumeDenied
				}
			}
		}
	}

	// Egress-network gate: if RUNSECURE_EGRESS_NETWORK is configured, only
	// containers with runsecure.role=proxy may attach it. Two attach paths
	// exist in the Docker API and both must be gated:
	//
	//   1. NetworkingConfig.EndpointsConfig[egressNet] — the explicit endpoint
	//      map used at container-create time.
	//   2. HostConfig.NetworkMode=<egressNet> — the alternate form Docker uses
	//      when the primary network is named directly via NetworkMode rather
	//      than EndpointsConfig (Bypass 1 in the Task 7 fix brief).
	//
	// Default-deny: absent label, empty label, or any role that is not exactly
	// "proxy" (including "runner") are all denied.
	if egressNet != "" {
		labels, _ := req["Labels"].(map[string]any)
		role, _ := labels["runsecure.role"].(string)

		nc, _ := req["NetworkingConfig"].(map[string]any)
		eps, _ := nc["EndpointsConfig"].(map[string]any)
		if _, attaches := eps[egressNet]; attaches {
			if role != "proxy" {
				return ErrEgressAttachDenied
			}
		}

		if nm, _ := hc["NetworkMode"].(string); nm == egressNet {
			if role != "proxy" {
				return ErrEgressAttachDenied
			}
		}
	}

	return nil
}

// ValidateNetworkCreate enforces driver=bridge, Internal=true, Attachable=false.
func ValidateNetworkCreate(body []byte) error {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("malformed JSON: %w", err)
	}
	if drv, _ := req["Driver"].(string); drv != "bridge" {
		return fmt.Errorf("Network Driver must be 'bridge', got %q", drv)
	}
	if internal, _ := req["Internal"].(bool); !internal {
		return errors.New("Network must have Internal: true")
	}
	if attachable, ok := req["Attachable"].(bool); ok && attachable {
		return errors.New("Network must have Attachable: false")
	}
	return nil
}

func containsString(v any, target string) bool {
	arr, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range arr {
		if s, ok := item.(string); ok && s == target {
			return true
		}
	}
	return false
}

func checkBinds(v any) error {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			continue
		}
		// SplitN extracts the host path before the first ":mode" suffix.
		// Removes the `i >= 0` boundary check (and its mutation surface).
		src := strings.SplitN(s, ":", 2)[0]
		for _, bad := range forbiddenBindPrefixes {
			if src == bad || strings.HasPrefix(src, bad+"/") {
				return fmt.Errorf("%w: %s", ErrBindForbidden, src)
			}
		}
		for _, bad := range forbiddenBindSuffixes {
			if strings.HasSuffix(src, bad) {
				return fmt.Errorf("%w: %s", ErrBindForbidden, src)
			}
		}
	}
	return nil
}
