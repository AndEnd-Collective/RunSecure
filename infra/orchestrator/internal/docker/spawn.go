package docker

import (
	"context"
	"fmt"
)

// SpawnInputs is the complete parameter set for a per-spawn container stack.
//
// Field names here match what orchestrator/spawn.go passes — keep them
// in sync if either changes.
type SpawnInputs struct {
	Scope, Repo, SpawnID string
	NetworkID            string // pre-created by caller; Spawn attaches containers to it
	RunnerImage          string // digest-pinned
	ProxyImage           string // digest-pinned
	SeccompProfilePath   string
	ResourcesMemory      int64 // bytes
	ResourcesNanoCPUs    int64 // 1e9 = 1 CPU
	ResourcesPIDs        int64
	JITConfigB64         string
	EgressConfigDir      string // host path bind-mounted into proxy containers
	Labels               []string // additional labels (key=value) merged onto every container
}

// Spawn creates and starts the 4-container per-spawn stack: squid + haproxy
// + dnsmasq + runner. All four are attached to the caller-provided network.
// Returns map of role → container ID. On any failure, rolls back created
// containers (caller deletes the network).
func Spawn(ctx context.Context, c Client, in SpawnInputs) (map[string]string, error) {
	created := map[string]string{}

	// Defensive rollback: on any error, delete every container we created.
	rollback := func() {
		for _, id := range created {
			_ = c.DeleteContainer(ctx, id, true)
		}
	}

	// Common labels every container in this spawn carries.
	commonLabels := map[string]string{
		"runsecure.scope":    in.Scope,
		"runsecure.repo":     in.Repo,
		"runsecure.spawn_id": in.SpawnID,
	}

	// Common HostConfig fragments.
	hcBase := HostConfig{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true"},
		NetworkMode:    in.NetworkID,
		ReadonlyRootfs: true,
		AutoRemove:     false,
	}

	// 1. squid container.
	squidLabels := merge(commonLabels, map[string]string{"runsecure.role": "squid"})
	squidHC := hcBase
	squidHC.Binds = []string{in.EgressConfigDir + "/squid.conf:/etc/squid/squid.conf:ro"}
	squidName := fmt.Sprintf("rs-%s-squid", in.SpawnID)
	squidID, err := c.CreateContainer(ctx, CreateContainerRequest{
		Name: squidName, Image: in.ProxyImage, User: "1001:0",
		Labels: squidLabels, HostConfig: squidHC,
	})
	if err != nil {
		rollback()
		return nil, fmt.Errorf("docker: create squid: %w", err)
	}
	created["squid"] = squidID

	// 2. haproxy container.
	haLabels := merge(commonLabels, map[string]string{"runsecure.role": "haproxy"})
	haHC := hcBase
	haHC.Binds = []string{in.EgressConfigDir + "/haproxy.cfg:/etc/haproxy/haproxy.cfg:ro"}
	haName := fmt.Sprintf("rs-%s-haproxy", in.SpawnID)
	haID, err := c.CreateContainer(ctx, CreateContainerRequest{
		Name: haName, Image: in.ProxyImage, User: "1001:0",
		Labels: haLabels, HostConfig: haHC,
	})
	if err != nil {
		rollback()
		return nil, fmt.Errorf("docker: create haproxy: %w", err)
	}
	created["haproxy"] = haID

	// 3. dnsmasq container.
	dnsLabels := merge(commonLabels, map[string]string{"runsecure.role": "dnsmasq"})
	dnsHC := hcBase
	dnsHC.Binds = []string{in.EgressConfigDir + "/dnsmasq.conf:/etc/dnsmasq.conf:ro"}
	dnsName := fmt.Sprintf("rs-%s-dnsmasq", in.SpawnID)
	dnsID, err := c.CreateContainer(ctx, CreateContainerRequest{
		Name: dnsName, Image: in.ProxyImage, User: "1001:0",
		Labels: dnsLabels, HostConfig: dnsHC,
	})
	if err != nil {
		rollback()
		return nil, fmt.Errorf("docker: create dnsmasq: %w", err)
	}
	created["dnsmasq"] = dnsID

	// 4. runner container.
	runnerLabels := merge(commonLabels, map[string]string{"runsecure.role": "runner"})
	runnerHC := hcBase
	runnerHC.Memory = in.ResourcesMemory
	runnerHC.NanoCPUs = in.ResourcesNanoCPUs
	runnerHC.PidsLimit = in.ResourcesPIDs
	runnerHC.Tmpfs = map[string]string{"/tmp": "noexec,nosuid,nodev,size=512m"}
	runnerName := fmt.Sprintf("rs-%s-runner", in.SpawnID)
	runnerID, err := c.CreateContainer(ctx, CreateContainerRequest{
		Name: runnerName, Image: in.RunnerImage, User: "1001:0",
		Env: []string{"RUNNER_JIT_CONFIG=" + in.JITConfigB64},
		Labels: runnerLabels, HostConfig: runnerHC,
	})
	if err != nil {
		rollback()
		return nil, fmt.Errorf("docker: create runner: %w", err)
	}
	created["runner"] = runnerID

	// Start all four (order matters: proxy stack must be ready before runner).
	for _, role := range []string{"squid", "haproxy", "dnsmasq", "runner"} {
		if err := c.StartContainer(ctx, created[role]); err != nil {
			rollback()
			return nil, fmt.Errorf("docker: start %s: %w", role, err)
		}
	}
	return created, nil
}

func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
