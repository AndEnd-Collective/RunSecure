package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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

// The create schemas intentionally cover the orchestrator's Docker client,
// plus explicitly refused legacy fields. Unknown Docker options fail closed:
// Mounts, VolumesFrom, Runtime, device requests and future daemon extensions
// must never bypass the same policy by introducing another configuration path.
type containerCreate struct {
	Image            string
	User             string
	Env              []string
	Cmd              []string
	Entrypoint       []string
	Labels           map[string]string
	HostConfig       hostConfig
	NetworkingConfig *networkingConfig
}

type hostConfig struct {
	Privileged     bool
	CapAdd         []string
	CapDrop        []string
	Devices        []json.RawMessage
	PidMode        string
	NetworkMode    string
	IpcMode        string
	UTSMode        string
	UsernsMode     string
	Sysctls        map[string]string
	SecurityOpt    []string
	Binds          []string
	Memory         int64
	NanoCPUs       int64 `json:"NanoCpus"`
	PidsLimit      int64
	ReadonlyRootfs bool
	AutoRemove     bool
	Tmpfs          map[string]string
}

type networkingConfig struct {
	EndpointsConfig map[string]endpointConfig
}

type endpointConfig struct {
	Aliases []string
}

type networkCreate struct {
	Name       string
	Driver     string
	Internal   bool
	Attachable bool
	Labels     map[string]string
}

// ValidateContainerCreate enforces the supported Docker create schema and
// containment policy before forwarding the original body. Keys are unique
// under case folding, schema field spelling is exact, and values are typed so
// the proxy and daemon cannot interpret different effective configurations.
// Only the designated egress volume may be bound, explicitly read-only, by a
// role=proxy container. An empty egressVol denies every bind. The existing
// egress network role gate is disabled only when egressNet is empty.
func ValidateContainerCreate(body []byte, images *imageallow.Allowlist, egressNet string, egressVol string) error {
	var req containerCreate
	if err := decodeCreate(body, &req); err != nil {
		return err
	}
	if !images.Allows(req.Image) {
		return ErrImageNotAllowed
	}
	if !nonRootIdentity(req.User) {
		return ErrUserRequired
	}
	hc := req.HostConfig
	if hc.Privileged {
		return ErrPrivilegedDenied
	}
	if len(hc.CapAdd) > 0 {
		return ErrCapAddDenied
	}
	if !slices.Contains(hc.CapDrop, "ALL") {
		return ErrCapDropMissingALL
	}
	if len(hc.Devices) > 0 {
		return ErrDevicesDenied
	}
	if hc.PidMode != "" {
		return ErrPidModeDenied
	}
	if hc.NetworkMode == "host" || hc.NetworkMode == "none" || strings.HasPrefix(hc.NetworkMode, "container:") {
		return ErrNetworkModeDenied
	}
	if hc.IpcMode != "" && hc.IpcMode != "private" {
		return ErrIpcModeDenied
	}
	if hc.UTSMode != "" {
		return ErrUTSModeDenied
	}
	if hc.UsernsMode != "" {
		return ErrUsernsModeDenied
	}
	if len(hc.Sysctls) > 0 {
		return ErrSysctlsDenied
	}
	if !slices.Contains(hc.SecurityOpt, "no-new-privileges:true") {
		return ErrSecurityOptMissingNoNewPrivs
	}
	// Docker's default seccomp profile remains active. The Engine API expects
	// custom seccomp JSON, while the old file-path option never loaded a profile;
	// accepting arbitrary JSON here would let a compromised controller disable
	// the default. Custom seccomp and LSM overrides are unsupported.
	if len(hc.SecurityOpt) != 1 {
		return errors.New("unsupported HostConfig.SecurityOpt: custom seccomp and LSM overrides are denied")
	}
	if err := checkBinds(hc.Binds, egressVol, req.Labels["runsecure.role"]); err != nil {
		return err
	}
	for target, options := range hc.Tmpfs {
		if !cleanMountTarget(target) {
			return errors.New("invalid HostConfig.Tmpfs target")
		}
		flags := strings.Split(options, ",")
		if !slices.Contains(flags, "noexec") || !slices.Contains(flags, "nosuid") || !slices.Contains(flags, "nodev") {
			return errors.New("HostConfig.Tmpfs requires noexec,nosuid,nodev")
		}
		seen := map[string]bool{}
		for _, flag := range flags {
			key, value, hasValue := strings.Cut(flag, "=")
			if seen[key] {
				return errors.New("duplicate HostConfig.Tmpfs option")
			}
			seen[key] = true
			switch key {
			case "noexec", "nosuid", "nodev":
				if hasValue {
					return errors.New("invalid HostConfig.Tmpfs flag")
				}
			case "size", "uid", "gid", "mode":
				if !hasValue || value == "" {
					return errors.New("invalid HostConfig.Tmpfs option")
				}
			default:
				return errors.New("unsupported HostConfig.Tmpfs option")
			}
		}
	}
	if egressNet != "" && req.Labels["runsecure.role"] != "proxy" {
		if req.NetworkingConfig != nil {
			if _, attaches := req.NetworkingConfig.EndpointsConfig[egressNet]; attaches {
				return ErrEgressAttachDenied
			}
		}
		if hc.NetworkMode == egressNet {
			return ErrEgressAttachDenied
		}
	}
	return nil
}

// ValidateNetworkCreate applies the same parser contract as container creates,
// then requires an internal, non-attachable bridge with ownership labels.
func ValidateNetworkCreate(body []byte) error {
	var req networkCreate
	if err := decodeCreate(body, &req); err != nil {
		return err
	}
	if req.Driver != "bridge" {
		return fmt.Errorf("Network Driver must be 'bridge', got %q", req.Driver)
	}
	if !req.Internal {
		return errors.New("Network must have Internal: true")
	}
	if req.Attachable {
		return errors.New("Network must have Attachable: false")
	}
	for _, key := range []string{"runsecure.scope", "runsecure.repo", "runsecure.spawn_id"} {
		if req.Labels[key] == "" {
			return fmt.Errorf("Network Labels[%q] is required", key)
		}
	}
	return nil
}

var numericIdentity = regexp.MustCompile(`^[1-9][0-9]*(:([0-9]|[1-9][0-9]*))?$`)
var volumeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)

func nonRootIdentity(user string) bool {
	if !numericIdentity.MatchString(user) {
		return false
	}
	for _, id := range strings.Split(user, ":") {
		if _, err := strconv.ParseUint(id, 10, 31); err != nil {
			return false
		}
	}
	return true
}

func cleanMountTarget(target string) bool {
	return strings.HasPrefix(target, "/") && target != "/" && path.Clean(target) == target && !strings.ContainsAny(target, "\x00:")
}

func checkBinds(binds []string, egressVol, role string) error {
	for _, bind := range binds {
		parts := strings.Split(bind, ":")
		if strings.HasPrefix(parts[0], "/") {
			return ErrBindForbidden
		}
		if len(parts) != 3 || !volumeName.MatchString(parts[0]) || egressVol == "" || parts[0] != egressVol || role != "proxy" || !cleanMountTarget(parts[1]) || parts[2] != "ro" {
			return ErrEgressVolumeDenied
		}
	}
	return nil
}

// decodeCreate checks lexical ambiguity before any map or struct decoder can
// discard duplicate keys. It also requires exact schema field names: Go's
// default case-insensitive struct matching must not widen our supported API.
func decodeCreate(body []byte, dst any) error {
	if !utf8.Valid(body) {
		return errors.New("JSON must be valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	value, err := uniqueJSONValue(dec, 0)
	if err != nil {
		return fmt.Errorf("malformed or ambiguous JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("JSON must contain one object")
	}
	if err := exactJSONFields(value, reflect.TypeOf(dst).Elem()); err != nil {
		return err
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("invalid create schema: %w", err)
	}
	return nil
}

func uniqueJSONValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("JSON nesting exceeds limit")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		seen := map[string]bool{}
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := token.(string)
			if !ok {
				return nil, errors.New("object key must be a string")
			}
			folded := strings.Map(func(r rune) rune {
				minimum := r
				for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
					if next < minimum {
						minimum = next
					}
				}
				return minimum
			}, key)
			if seen[folded] {
				return nil, fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[folded] = true
			value, err := uniqueJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		var array []any
		for dec.More() {
			value, err := uniqueJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return array, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

func exactJSONFields(value any, schema reflect.Type) error {
	if value == nil && schema.Kind() == reflect.Pointer {
		return nil
	}
	if schema.Kind() == reflect.Pointer {
		schema = schema.Elem()
	}
	switch schema.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("create configuration must be an object")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < schema.NumField(); i++ {
			field := schema.Field(i)
			name := field.Tag.Get("json")
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for key, child := range object {
			field, ok := fields[key]
			if !ok {
				return fmt.Errorf("unsupported create field %q", key)
			}
			if err := exactJSONFields(child, field); err != nil {
				return err
			}
		}
	case reflect.Map:
		if object, ok := value.(map[string]any); ok {
			for _, child := range object {
				if err := exactJSONFields(child, schema.Elem()); err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		if array, ok := value.([]any); ok {
			for _, child := range array {
				if err := exactJSONFields(child, schema.Elem()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
