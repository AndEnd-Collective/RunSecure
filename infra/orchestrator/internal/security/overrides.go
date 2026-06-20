package security

import (
	"fmt"
	"net"
)

// ApplyProjectOverrides merges a project's runner.yml security_overrides into
// the scope's baseline Policy, restricted to the keys listed in
// allowProjectOverrides. Disallowed override keys are silently ignored.
//
// Returns error only for type-mismatches in override values.
func ApplyProjectOverrides(base Policy, allowProjectOverrides []string, overrides map[string]any) (Policy, error) {
	allowed := map[string]bool{}
	for _, k := range allowProjectOverrides {
		allowed[k] = true
	}
	for k, raw := range overrides {
		if !allowed[k] {
			continue
		}
		switch k {
		case "allow_wildcards":
			arr, ok := raw.([]any)
			if !ok {
				return base, fmt.Errorf("security: allow_wildcards must be a list of strings")
			}
			ents := make([]string, 0, len(arr))
			for _, v := range arr {
				s, ok := v.(string)
				if !ok {
					return base, fmt.Errorf("security: allow_wildcards entries must be strings")
				}
				ents = append(ents, s)
			}
			base.WildcardEntries = ents
			if len(ents) > 0 {
				base.AllowWildcards = true
			}
		case "allow_doh":
			arr, ok := raw.([]any)
			if !ok {
				if b, ok := raw.(bool); ok && b {
					base.AllowDoH = true
				}
				continue
			}
			for _, v := range arr {
				if s, ok := v.(string); ok {
					base.DoHProviders = append(base.DoHProviders, s)
				}
			}
			if len(base.DoHProviders) > 0 {
				base.AllowDoH = true
			}
		case "allow_imds":
			if b, ok := raw.(bool); ok {
				base.AllowIMDS = b
			}
		case "allow_kube_api":
			if b, ok := raw.(bool); ok {
				base.AllowKubeAPI = b
			}
		case "allow_private_cidrs":
			arr, ok := raw.([]any)
			if !ok {
				return base, fmt.Errorf("security: allow_private_cidrs must be a list of strings")
			}
			parsed := make([]*net.IPNet, 0, len(arr))
			for _, v := range arr {
				s, ok := v.(string)
				if !ok {
					return base, fmt.Errorf("security: allow_private_cidrs entries must be strings")
				}
				_, cidr, err := net.ParseCIDR(s)
				if err != nil {
					return base, fmt.Errorf("security: allow_private_cidrs: invalid CIDR %q: %w", s, err)
				}
				parsed = append(parsed, cidr)
			}
			base.AllowedPrivateCIDRs = parsed
		}
	}
	return base, nil
}
