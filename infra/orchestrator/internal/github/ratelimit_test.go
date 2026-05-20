package github

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRateLimit_HappyPath(t *testing.T) {
	h := http.Header{}
	h.Set("X-RateLimit-Limit", "5000")
	h.Set("X-RateLimit-Remaining", "4321")
	h.Set("X-RateLimit-Reset", "1747656000")

	r := ParseRateLimit(h)
	require.Equal(t, 5000, r.Limit)
	require.Equal(t, 4321, r.Remaining)
	require.Equal(t, int64(1747656000), r.ResetUnix)
}

func TestParseRateLimit_MissingHeaders_Zero(t *testing.T) {
	r := ParseRateLimit(http.Header{})
	require.Equal(t, 0, r.Limit)
	require.Equal(t, 0, r.Remaining)
	require.Equal(t, int64(0), r.ResetUnix)
}
