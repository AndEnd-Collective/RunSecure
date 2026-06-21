package security

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCheckEgressIPLiterals_Hostname verifies that a hostname (non-IP) is skipped.
func TestCheckEgressIPLiterals_Hostname(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"db.neon.tech:5432"}, Policy{})
	require.NoError(t, err, "hostname must be skipped — only literal IPs are checked")
}

// TestCheckEgressIPLiterals_AllowedPrivateCIDR verifies that a private IP within
// an operator-provided opt-in CIDR is accepted.
func TestCheckEgressIPLiterals_AllowedPrivateCIDR(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	p := Policy{AllowedPrivateCIDRs: []*net.IPNet{cidr}}
	err = CheckEgressIPLiterals([]string{"10.0.0.5:5432"}, p)
	require.NoError(t, err, "10.0.0.5 is within the operator-allowed 10.0.0.0/8")
}

// TestCheckEgressIPLiterals_PrivateIPBlocked verifies that a private IP with no
// opt-in is rejected.
func TestCheckEgressIPLiterals_PrivateIPBlocked(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"10.0.0.5:5432"}, Policy{})
	require.Error(t, err, "10.0.0.5 must be rejected with empty opt-in")
	require.Contains(t, err.Error(), "security:")
}

// TestCheckEgressIPLiterals_EmptyList verifies that an empty host list is allowed.
func TestCheckEgressIPLiterals_EmptyList(t *testing.T) {
	err := CheckEgressIPLiterals([]string{}, Policy{})
	require.NoError(t, err)
}

// TestCheckEgressIPLiterals_MetadataEndpoint verifies cloud metadata IP is blocked.
func TestCheckEgressIPLiterals_MetadataEndpoint(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"169.254.169.254:80"}, Policy{})
	require.Error(t, err, "169.254.169.254 (cloud metadata) must be blocked")
	require.Contains(t, err.Error(), "security:")
}

// TestCheckEgressIPLiterals_Loopback verifies loopback IPv4 is blocked.
func TestCheckEgressIPLiterals_Loopback(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"127.0.0.1:5432"}, Policy{})
	require.Error(t, err, "127.0.0.1 (loopback) must be blocked")
	require.Contains(t, err.Error(), "security:")
}

// TestCheckEgressIPLiterals_IPv6Loopback verifies IPv6 loopback in bracket notation is blocked.
func TestCheckEgressIPLiterals_IPv6Loopback(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"[::1]:5432"}, Policy{})
	require.Error(t, err, "::1 (IPv6 loopback) must be blocked")
	require.Contains(t, err.Error(), "security:")
}

// TestCheckEgressIPLiterals_BareIPv6Loopback verifies that a bare IPv6 loopback
// address (no brackets, no port) is not silently bypassed.
func TestCheckEgressIPLiterals_BareIPv6Loopback(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"::1"}, Policy{})
	require.Error(t, err, "bare ::1 (IPv6 loopback, no brackets) must be blocked")
	require.Contains(t, err.Error(), "security:")
}

// TestCheckEgressIPLiterals_UnspecifiedIPv4 verifies 0.0.0.0 is blocked.
func TestCheckEgressIPLiterals_UnspecifiedIPv4(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"0.0.0.0:5432"}, Policy{})
	require.Error(t, err, "0.0.0.0 must be blocked")
	require.Contains(t, err.Error(), "security:")
}

// TestCheckEgressIPLiterals_RFC1918_Class_C verifies 192.168.x.x is blocked.
func TestCheckEgressIPLiterals_RFC1918_Class_C(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"192.168.1.1:5432"}, Policy{})
	require.Error(t, err, "192.168.1.1 (RFC1918) must be blocked")
	require.Contains(t, err.Error(), "security:")
}

// TestCheckEgressIPLiterals_RFC1918_172 verifies 172.16.x.x is blocked.
func TestCheckEgressIPLiterals_RFC1918_172(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"172.16.0.1:5432"}, Policy{})
	require.Error(t, err, "172.16.0.1 (RFC1918) must be blocked")
	require.Contains(t, err.Error(), "security:")
}

// TestCheckEgressIPLiterals_HTTPEgress_NoPort verifies http_egress style (no port) is checked.
func TestCheckEgressIPLiterals_HTTPEgress_NoPort(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"169.254.169.254"}, Policy{})
	require.Error(t, err, "169.254.169.254 (no port, http_egress style) must be blocked")
	require.Contains(t, err.Error(), "security:")
}

// TestCheckEgressIPLiterals_PublicIP verifies that a public (non-private) literal
// IP address is accepted with an empty policy.
func TestCheckEgressIPLiterals_PublicIP(t *testing.T) {
	err := CheckEgressIPLiterals([]string{"8.8.8.8:53"}, Policy{})
	require.NoError(t, err, "public IP 8.8.8.8 must not be blocked")
}

// TestMustBuildBlockedRanges_PanicOnBadCIDR covers the panic branch in
// mustBuildBlockedRanges (egressip.go init path). The production parseFn is
// net.ParseCIDR and always succeeds; here we inject an error-returning stub.
func TestMustBuildBlockedRanges_PanicOnBadCIDR(t *testing.T) {
	badParseFn := func(s string) (net.IP, *net.IPNet, error) {
		return nil, nil, errors.New("injected parse failure")
	}
	require.Panics(t, func() {
		mustBuildBlockedRanges(badParseFn, []string{"not-a-cidr"})
	}, "mustBuildBlockedRanges must panic when parseFn returns an error")
}

// TestApplyOverrides_AllowPrivateCIDRs verifies that allow_private_cidrs parses
// and wires up AllowedPrivateCIDRs on the Policy.
func TestApplyOverrides_AllowPrivateCIDRs(t *testing.T) {
	base := Defaults("strict")
	merged, err := ApplyProjectOverrides(base,
		[]string{"allow_private_cidrs"},
		map[string]any{"allow_private_cidrs": []any{"10.0.0.0/8"}},
	)
	require.NoError(t, err)
	require.Len(t, merged.AllowedPrivateCIDRs, 1)
	ip := net.ParseIP("10.1.2.3")
	require.True(t, merged.AllowedPrivateCIDRs[0].Contains(ip),
		"10.1.2.3 must be within the parsed 10.0.0.0/8 CIDR")
}

// TestApplyOverrides_AllowPrivateCIDRs_BadCIDR verifies that an invalid CIDR
// string causes ApplyProjectOverrides to return an error (fail-closed).
func TestApplyOverrides_AllowPrivateCIDRs_BadCIDR(t *testing.T) {
	base := Defaults("strict")
	_, err := ApplyProjectOverrides(base,
		[]string{"allow_private_cidrs"},
		map[string]any{"allow_private_cidrs": []any{"not-a-cidr"}},
	)
	require.Error(t, err, "bad CIDR must cause a parse error")
	require.Contains(t, err.Error(), "security:")
}
