package proxy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRouteAllowed_ContainersAndNetworks(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		// allowed
		{http.MethodGet, "/v1.43/info", true},
		{http.MethodGet, "/v1.43/version", true},
		{http.MethodGet, "/v1.43/containers/json", true},
		{http.MethodGet, "/v1.43/containers/abc/json", true},
		{http.MethodPost, "/v1.43/containers/create", true},
		{http.MethodPost, "/v1.43/containers/abc/start", true},
		{http.MethodDelete, "/v1.43/containers/abc", true},
		{http.MethodPost, "/v1.43/networks/create", true},
		{http.MethodDelete, "/v1.43/networks/xyz", true},
		{http.MethodPost, "/v1.43/networks/xyz/connect", true},
		{http.MethodGet, "/v1.44/info", true},

		// blocked
		{http.MethodPost, "/v1.43/containers/abc/exec", false},
		{http.MethodPost, "/v1.43/containers/abc/attach", false},
		{http.MethodPost, "/v1.43/build", false},
		{http.MethodPost, "/v1.43/images/create", false},
		{http.MethodPost, "/v1.43/volumes/create", false},
		{http.MethodGet, "/v1.43/images/json", false},
		{http.MethodGet, "/", false},
		{http.MethodPost, "/v1.43/containers/abc/exec/whatever", false},
	}
	for _, c := range cases {
		got := RouteAllowed(c.method, c.path)
		require.Equal(t, c.want, got, "%s %s", c.method, c.path)
	}
}

func TestRouteAllowed_VersionOnlyPath_FallsThroughToRoot(t *testing.T) {
	// /v1.43 alone becomes "/" after stripping; no allowlist rule matches "/" → false.
	require.False(t, RouteAllowed(http.MethodGet, "/v1.43"))
}
