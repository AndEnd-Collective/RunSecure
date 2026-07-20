// Command orchestrator runs one scope of the RunSecure compose-backend
// runner orchestrator. See infra/orchestrator/README.md for usage.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Set by Docker builds via -ldflags. Local go builds intentionally retain the
// explicit development values.
var (
	version  = "dev"
	buildSHA = "unknown"
)

//coverage:ignore main is a thin entrypoint; tested via integration tests
func main() {
	args := os.Args[1:]
	if len(args) >= 1 {
		switch args[0] {
		case "healthcheck":
			os.Exit(runHealthcheck())
		case "status":
			os.Exit(runStatus())
		case "version":
			fmt.Printf("runsecure-orchestrator %s (%s)\n", version, buildSHA)
			return
		}
	}

	scopePath := os.Getenv("RUNSECURE_SCOPE_FILE")
	if scopePath == "" {
		fmt.Fprintln(os.Stderr, "orchestrator: RUNSECURE_SCOPE_FILE env required")
		os.Exit(2)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Run(ctx, scopePath); err != nil {
		fmt.Fprintln(os.Stderr, "orchestrator:", err)
		os.Exit(1)
	}
}

//coverage:ignore Self-curl over loopback for docker HEALTHCHECK
func runHealthcheck() int {
	c := http.Client{Timeout: 2 * time.Second}
	r, err := c.Get("http://localhost:8080/healthz")
	if err != nil {
		return 1
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return 1
	}
	return 0
}

//coverage:ignore Self-curl for `orchestrator status` operator CLI
func runStatus() int {
	c := http.Client{Timeout: 2 * time.Second}
	r, err := c.Get("http://localhost:8081/state/snapshot")
	if err != nil {
		return 1
	}
	defer r.Body.Close()
	_, _ = c.Get("") // keep imports used
	fmt.Println(r.Status)
	return 0
}
