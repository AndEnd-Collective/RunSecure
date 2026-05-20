package security

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStrictDefaults(t *testing.T) {
	p := Defaults("strict")
	require.False(t, p.AllowWildcards)
	require.False(t, p.AllowDoH)
	require.False(t, p.AllowIMDS)
	require.False(t, p.AllowKubeAPI)
	require.False(t, p.AllowMeshInject)
	require.False(t, p.AllowDNSSuffixMatch)
}

func TestStandardDefaults(t *testing.T) {
	p := Defaults("standard")
	require.True(t, p.AllowWildcards)
	require.False(t, p.AllowDoH)
	require.False(t, p.AllowIMDS)
	require.False(t, p.AllowKubeAPI)
	require.False(t, p.AllowMeshInject)
	require.True(t, p.AllowDNSSuffixMatch)
}

func TestPermissiveDefaults(t *testing.T) {
	p := Defaults("permissive")
	require.True(t, p.AllowWildcards)
	require.True(t, p.AllowDoH)
	require.True(t, p.AllowIMDS)
	require.True(t, p.AllowKubeAPI)
	require.True(t, p.AllowMeshInject)
	require.True(t, p.AllowDNSSuffixMatch)
}

func TestCustomDefaultsEmpty(t *testing.T) {
	p := Defaults("custom")
	require.False(t, p.AllowWildcards)
}

func TestUnknownProfile_Strict(t *testing.T) {
	p := Defaults("bogus")
	require.False(t, p.AllowWildcards)
}
