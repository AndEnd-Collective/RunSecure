// Package security implements the policy knobs from spec §4.4 and the
// merge logic for per-project overrides bounded by scope.allow_project_overrides.
//
// The structural floor (§4.3) is NOT configurable here — those four
// properties are enforced by other components (network internal=true,
// runner cap_drop=ALL, no-new-privileges, proxy RO rootfs). This package
// only handles the policy knobs ABOVE that floor.
package security

import "net"

// Policy is the resolved policy after applying preset defaults + overrides.
type Policy struct {
	AllowWildcards      bool
	AllowDoH            bool
	AllowIMDS           bool
	AllowKubeAPI        bool
	AllowMeshInject     bool
	AllowDNSSuffixMatch bool

	// Explicit per-project lists ALWAYS win (spec: "user autonomy"):
	WildcardEntries    []string     // explicit *.foo.com entries from runner.yml
	DoHProviders       []string     // explicit DoH domains the project lists
	IMDSEndpoints      []string     // explicit IMDS CIDRs the project lists
	AllowedPrivateCIDRs []*net.IPNet // operator opt-in private ranges for literal-IP egress
}

// Defaults returns the baseline Policy for a preset name.
func Defaults(profile string) Policy {
	switch profile {
	case "strict":
		return Policy{}
	case "standard":
		return Policy{
			AllowWildcards:      true,
			AllowDNSSuffixMatch: true,
		}
	case "permissive":
		return Policy{
			AllowWildcards:      true,
			AllowDoH:            true,
			AllowIMDS:           true,
			AllowKubeAPI:        true,
			AllowMeshInject:     true,
			AllowDNSSuffixMatch: true,
		}
	case "custom":
		return Policy{} // caller fills in
	default:
		return Policy{} // safest default
	}
}
