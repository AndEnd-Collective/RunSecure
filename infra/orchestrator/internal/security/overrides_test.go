package security

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyOverrides_ExplicitWildcardListWins(t *testing.T) {
	base := Defaults("strict") // wildcards: false
	merged, err := ApplyProjectOverrides(base,
		[]string{"allow_wildcards"},
		map[string]any{"allow_wildcards": []any{"*.amazonaws.com"}},
	)
	require.NoError(t, err)
	require.True(t, merged.AllowWildcards)
	require.Equal(t, []string{"*.amazonaws.com"}, merged.WildcardEntries)
}

func TestApplyOverrides_DisallowedOverrideSilentlyIgnored(t *testing.T) {
	base := Defaults("strict")
	merged, err := ApplyProjectOverrides(base,
		[]string{"allow_wildcards"},
		map[string]any{"allow_imds": true, "allow_wildcards": []any{"*.foo"}},
	)
	require.NoError(t, err)
	require.True(t, merged.AllowWildcards)
	require.False(t, merged.AllowIMDS, "allow_imds was NOT in allow_project_overrides — must be ignored")
}

func TestApplyOverrides_AllowDoHList(t *testing.T) {
	base := Defaults("strict")
	merged, err := ApplyProjectOverrides(base,
		[]string{"allow_doh"},
		map[string]any{"allow_doh": []any{"cloudflare-dns.com", "dns.google"}},
	)
	require.NoError(t, err)
	require.True(t, merged.AllowDoH)
	require.Equal(t, []string{"cloudflare-dns.com", "dns.google"}, merged.DoHProviders)
}

func TestApplyOverrides_AllowDoHBool(t *testing.T) {
	base := Defaults("strict")
	merged, err := ApplyProjectOverrides(base,
		[]string{"allow_doh"},
		map[string]any{"allow_doh": true},
	)
	require.NoError(t, err)
	require.True(t, merged.AllowDoH)
}

func TestApplyOverrides_AllowIMDSBool(t *testing.T) {
	base := Defaults("strict")
	merged, err := ApplyProjectOverrides(base,
		[]string{"allow_imds"},
		map[string]any{"allow_imds": true},
	)
	require.NoError(t, err)
	require.True(t, merged.AllowIMDS)
}

func TestApplyOverrides_AllowKubeAPIBool(t *testing.T) {
	base := Defaults("strict")
	merged, err := ApplyProjectOverrides(base,
		[]string{"allow_kube_api"},
		map[string]any{"allow_kube_api": true},
	)
	require.NoError(t, err)
	require.True(t, merged.AllowKubeAPI)
}

func TestApplyOverrides_WildcardsTypeMismatch(t *testing.T) {
	_, err := ApplyProjectOverrides(Defaults("strict"),
		[]string{"allow_wildcards"},
		map[string]any{"allow_wildcards": "not a list"},
	)
	require.ErrorContains(t, err, "allow_wildcards")
}

func TestApplyOverrides_WildcardElementTypeMismatch(t *testing.T) {
	_, err := ApplyProjectOverrides(Defaults("strict"),
		[]string{"allow_wildcards"},
		map[string]any{"allow_wildcards": []any{42}},
	)
	require.ErrorContains(t, err, "must be strings")
}

// Mutation kill: overrides.go:50 — `if len(base.DoHProviders) > 0`.
// Without the >0 check, setting an empty DoH list would still flip
// AllowDoH=true. With it, only non-empty lists do.
func TestApplyOverrides_EmptyDoHListDoesNotSetFlag(t *testing.T) {
	merged, err := ApplyProjectOverrides(Defaults("strict"),
		[]string{"allow_doh"},
		map[string]any{"allow_doh": []any{}}, // empty
	)
	require.NoError(t, err)
	require.False(t, merged.AllowDoH, "empty DoH list must not flip AllowDoH=true")
	require.Empty(t, merged.DoHProviders)
}

func TestApplyOverrides_UnknownKeyIgnored(t *testing.T) {
	merged, err := ApplyProjectOverrides(Defaults("strict"),
		[]string{"allow_wildcards", "unknown"},
		map[string]any{"unknown": "value"},
	)
	require.NoError(t, err)
	require.False(t, merged.AllowWildcards)
}
