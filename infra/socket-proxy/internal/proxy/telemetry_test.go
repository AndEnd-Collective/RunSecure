package proxy

import (
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuditDeniedRequestDoesNotReceiveUntrustedBodyURLOrHeaders(t *testing.T) {
	s := New("/nonexistent/sock", nil)
	var events []string
	s.SetEventLogger(func(kind, code string, status int) {
		events = append(events, kind+":"+code)
		require.Equal(t, 403, status)
	})
	r := httptest.NewRequest(http.MethodPost, "/containers/secret-in-path/exec?token=secret-in-query", nil)
	r.Header.Set("Authorization", "Bearer secret-in-header")
	response := httptest.NewRecorder()
	s.ServeHTTP(response, r)
	require.Equal(t, 403, response.Code)
	require.Equal(t, []string{"denied:route_not_allowed"}, events)
}

func TestAuditUpstreamFailureRemains502AndEmitsOnlyStableClass(t *testing.T) {
	s := New("/nonexistent/secret-file", nil)
	var events []string
	s.SetEventLogger(func(kind, code string, status int) {
		events = append(events, kind+":"+code)
		require.Equal(t, 502, status)
	})
	response := httptest.NewRecorder()
	s.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/info?secret=query", nil))
	require.Equal(t, 502, response.Code)
	require.Equal(t, []string{"upstream_failed:docker_transport_failed"}, events)
}
