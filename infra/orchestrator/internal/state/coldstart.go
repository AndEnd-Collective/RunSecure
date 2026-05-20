package state

import "github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"

// Orphan describes a proxy-role container with no matching runner — the
// caller (orchestrator.Run) tears these down before resuming normal
// operation. Used for cold-start reconciliation.
type Orphan struct {
	ContainerID string
	SpawnID     string
}

// RebuildFromDocker reconstructs in-flight counters from a list of
// docker containers labelled for our scope. Containers are categorised by
// runsecure.role:
//   - "runner" → increment in-flight for the repo
//   - "proxy"  → record under the spawn-id; if no runner with same spawn-id
//                exists, it's an orphan and the caller should tear down
//
// Returns the list of orphans. Idempotent.
func RebuildFromDocker(s *State, listed []docker.Container) []Orphan {
	runnerSpawns := map[string]bool{}
	type proxyEntry struct{ containerID, spawnID string }
	proxies := []proxyEntry{}

	for _, c := range listed {
		role := c.Labels["runsecure.role"]
		spawnID := c.Labels["runsecure.spawn_id"]
		repo := c.Labels["runsecure.repo"]

		switch role {
		case "runner":
			if spawnID != "" {
				runnerSpawns[spawnID] = true
			}
			if repo != "" {
				s.IncrementInFlight(repo)
			}
		case "proxy", "squid", "haproxy", "dnsmasq":
			proxies = append(proxies, proxyEntry{containerID: c.ID, spawnID: spawnID})
		}
	}

	orphans := []Orphan{}
	for _, p := range proxies {
		if !runnerSpawns[p.spawnID] {
			orphans = append(orphans, Orphan{ContainerID: p.containerID, SpawnID: p.spawnID})
		}
	}
	return orphans
}
