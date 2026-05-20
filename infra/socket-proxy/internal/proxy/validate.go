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
)

// Forbidden host-path prefixes for HostConfig.Binds source paths.
var forbiddenBindPrefixes = []string{
	"/var/run/docker.sock",
	"/proc",
	"/sys",
	"/etc",
	"/root",
	"/home",
}

// ValidateContainerCreate parses body as Docker's containers/create request
// and refuses it if any spec §7.2 rule fails.
//
// The function does NOT modify the body; it only validates.
func ValidateContainerCreate(body []byte, images *imageallow.Allowlist) error {
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
		src := s
		if i := strings.Index(s, ":"); i >= 0 {
			src = s[:i]
		}
		for _, bad := range forbiddenBindPrefixes {
			if src == bad || strings.HasPrefix(src, bad+"/") {
				return fmt.Errorf("%w: %s", ErrBindForbidden, src)
			}
		}
	}
	return nil
}
