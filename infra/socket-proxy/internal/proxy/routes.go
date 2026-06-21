// Package proxy implements the docker-socket-proxy core.
//
// Two layers of defense:
//  1. RouteAllowed: explicit method+path allowlist. Refuses anything outside it.
//  2. ValidateContainerCreate: body validation on POST /containers/create.
//
// Both must pass for a request to reach dockerd.
package proxy

import (
	"regexp"
)

// Versioned Docker API path prefix, e.g. /v1.43 or /v1.44.0
var versionPrefix = regexp.MustCompile(`^/v\d+\.\d+(\.\d+)?`)

// Per-endpoint regex compiled once.
var allowedRoutes = []struct {
	method string
	pathRe *regexp.Regexp
}{
	{"GET", regexp.MustCompile(`^/info$`)},
	{"GET", regexp.MustCompile(`^/version$`)},
	{"GET", regexp.MustCompile(`^/containers/json$`)},
	{"GET", regexp.MustCompile(`^/containers/[^/]+/json$`)},
	{"POST", regexp.MustCompile(`^/containers/create$`)},
	{"POST", regexp.MustCompile(`^/containers/[^/]+/start$`)},
	{"DELETE", regexp.MustCompile(`^/containers/[^/]+$`)},
	{"POST", regexp.MustCompile(`^/networks/create$`)},
	{"DELETE", regexp.MustCompile(`^/networks/[^/]+$`)},
	// POST /networks/{id}/connect is intentionally absent: the orchestrator
	// docker client only uses CreateNetwork and DeleteNetwork (no ConnectNetwork
	// method exists in internal/docker/client.go). Leaving this route open
	// would give an attacker a second path to attach a runner container to
	// the egress network post-create (Bypass 2 in the Task 7 fix brief).
}

// RouteAllowed reports whether method+path is on the allowlist.
//
// The path may or may not have an API-version prefix; we strip it before
// matching so /v1.43/info and /v1.44/info both match the /info rule.
func RouteAllowed(method, path string) bool {
	stripped := versionPrefix.ReplaceAllString(path, "")
	if stripped == "" {
		stripped = "/"
	}
	for _, r := range allowedRoutes {
		if r.method == method && r.pathRe.MatchString(stripped) {
			return true
		}
	}
	return false
}
