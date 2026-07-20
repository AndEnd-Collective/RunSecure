package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
)

type coldStartDocker interface {
	ListContainersForScope(ctx context.Context, scope string) ([]docker.Container, error)
	DeleteContainer(ctx context.Context, id string, force bool) error
}

type coldStartGitHub interface {
	ListRunners(ctx context.Context, repo string) ([]github.Runner, github.RateLimit, error)
	DeleteRunner(ctx context.Context, repo string, runnerID int64) error
}

// cleanupRecoveredSpawns fails closed instead of rebuilding anonymous
// in-flight counters. A restarted process cannot safely observe or release the
// old workers, so adopting them would consume scheduler capacity forever.
// Exact JIT registrations are removed before their containers; if GitHub is
// unavailable, the containers are left intact and startup fails for retry.
func cleanupRecoveredSpawns(
	ctx context.Context,
	scope string,
	configuredRepos []string,
	dc coldStartDocker,
	gh coldStartGitHub,
) error {
	containers, err := dc.ListContainersForScope(ctx, scope)
	if err != nil {
		return fmt.Errorf("cold-start: list recovered containers: %w", err)
	}
	allowed := make(map[string]bool, len(configuredRepos))
	for _, repo := range configuredRepos {
		allowed[repo] = true
	}
	wanted := map[string]map[string]bool{}
	owned := make([]docker.Container, 0, len(containers))
	for _, container := range containers {
		role := container.Labels["runsecure.role"]
		spawnID := container.Labels["runsecure.spawn_id"]
		if spawnID == "" {
			if role == "runner" || role == "proxy" {
				return fmt.Errorf("cold-start: recovered container %q has invalid spawn labels", container.ID)
			}
			continue
		}
		if role != "runner" && role != "proxy" {
			return fmt.Errorf("cold-start: recovered container %q has invalid spawn labels", container.ID)
		}
		owned = append(owned, container)
		if role != "runner" {
			continue
		}
		repo := container.Labels["runsecure.repo"]
		name := "rs-" + spawnID + "-runner"
		if !allowed[repo] || container.Name != name {
			return fmt.Errorf("cold-start: recovered runner %q has invalid ownership labels", container.ID)
		}
		if wanted[repo] == nil {
			wanted[repo] = map[string]bool{}
		}
		wanted[repo][name] = true
	}
	if len(owned) == 0 {
		return nil
	}

	repos := make([]string, 0, len(wanted))
	for repo := range wanted {
		repos = append(repos, repo)
	}
	sort.Strings(repos)
	for _, repo := range repos {
		runners, _, err := gh.ListRunners(ctx, repo)
		if err != nil {
			return fmt.Errorf("cold-start: list runners for %s: %w", repo, err)
		}
		for _, runner := range runners {
			if !wanted[repo][runner.Name] {
				continue
			}
			if err := gh.DeleteRunner(ctx, repo, runner.ID); err != nil {
				return fmt.Errorf("cold-start: delete runner %d for %s: %w", runner.ID, repo, err)
			}
		}
	}

	ids := make([]string, 0, len(owned))
	for _, container := range owned {
		ids = append(ids, container.ID)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := dc.DeleteContainer(ctx, id, true); err != nil {
			return fmt.Errorf("cold-start: delete recovered container %s: %w", id, err)
		}
	}
	return nil
}
