package state

import "github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"

// PerRepoDelta is the correction applied to a single repo's in-flight
// counter during reconciliation. delta = listed - in_memory.
type PerRepoDelta struct {
	Repo  string
	Delta int
}

// Reconcile compares the orchestrator's in-memory in-flight counts against
// the runner containers actually present in docker. Discrepancies are
// resolved by treating docker as the source of truth.
//
// Returns: net delta across all repos, plus the per-repo corrections.
// Caller (poll loop) emits drift.reconciled when |totalDelta| > 0.
func Reconcile(s *State, listed []docker.Container) (totalDelta int, perRepo []PerRepoDelta) {
	// Count runners per repo in the docker list.
	dockerCounts := map[string]int{}
	for _, c := range listed {
		if c.Labels["runsecure.role"] != "runner" {
			continue
		}
		dockerCounts[c.Labels["runsecure.repo"]]++
	}

	// Compare against in-memory and apply corrections.
	memRepos := s.AllRepos()
	seen := map[string]bool{}
	for _, repo := range memRepos {
		seen[repo] = true
		got := dockerCounts[repo]
		mem := s.InFlight(repo)
		if got != mem {
			delta := got - mem
			perRepo = append(perRepo, PerRepoDelta{Repo: repo, Delta: delta})
			totalDelta += delta
			// Apply the correction.
			if delta > 0 {
				for i := 0; i < delta; i++ {
					s.IncrementInFlight(repo)
				}
			} else {
				for i := 0; i < -delta; i++ {
					s.DecrementInFlight(repo)
				}
			}
		}
	}
	// Repos in docker but not in memory.
	for repo, got := range dockerCounts {
		if seen[repo] || got == 0 {
			continue
		}
		perRepo = append(perRepo, PerRepoDelta{Repo: repo, Delta: got})
		totalDelta += got
		for i := 0; i < got; i++ {
			s.IncrementInFlight(repo)
		}
	}
	return totalDelta, perRepo
}
