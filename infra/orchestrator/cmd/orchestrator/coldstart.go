package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/kube"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/orchestrator"
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
	wanted := map[string]bool{}
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
		wanted[name] = true
	}
	if err := cleanupRecoveredRunnerRegistrations(
		ctx, scope, configuredRepos, wanted, gh,
	); err != nil {
		return err
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

// cleanupRecoveredKubeSpawns performs the Kubernetes equivalent of the
// Compose cold-start cleanup. Recovered JIT registrations are identified by
// the exact deterministic runner names derived from reconciled, scope-owned
// Pods. Every configured repository is listed successfully before any delete
// occurs; then registrations are removed before their owning Secrets.
func cleanupRecoveredKubeSpawns(
	ctx context.Context,
	scope string,
	configuredRepos []string,
	be backend.Backend,
	gh coldStartGitHub,
) error {
	handles, err := be.Reconcile(ctx, scope)
	if err != nil {
		return fmt.Errorf("cold-start: reconcile recovered kube spawns: %w", err)
	}
	wanted, err := validateRecoveredKubeHandles(scope, configuredRepos, handles)
	if err != nil {
		return err
	}
	if err := cleanupRecoveredRunnerRegistrations(
		ctx, scope, configuredRepos, wanted, gh,
	); err != nil {
		return err
	}

	sort.Slice(handles, func(i, j int) bool { return handles[i].SpawnID < handles[j].SpawnID })
	for _, handle := range handles {
		if err := be.Teardown(ctx, handle, true); err != nil {
			return fmt.Errorf("cold-start: teardown recovered kube spawn %s: %w", handle.SpawnID, err)
		}
	}
	return nil
}

func validateRecoveredKubeHandles(
	scope string,
	configuredRepos []string,
	handles []backend.Handle,
) (map[string]bool, error) {
	wanted := make(map[string]bool, len(handles))
	seen := make(map[string]bool, len(handles))
	allowedRepoLabels := make(map[string]bool, len(configuredRepos))
	for _, repo := range configuredRepos {
		allowedRepoLabels[kube.RepoLabel(repo)] = true
	}
	expectedNamespace := kube.Namespace(scope)
	for _, handle := range handles {
		spawnID := handle.SpawnID
		if handle.Backend != "kube" || spawnID == "" || seen[spawnID] ||
			handle.Refs["namespace"] != expectedNamespace ||
			handle.Refs["secret"] != "rs-secret-"+spawnID ||
			handle.Refs["runner_pod"] != "rs-runner-"+spawnID ||
			!allowedRepoLabels[handle.Refs["repo_label"]] {
			return nil, fmt.Errorf("cold-start: recovered kube spawn %q has invalid ownership", spawnID)
		}
		seen[spawnID] = true
		wanted["rs-"+spawnID+"-runner"] = true
	}
	return wanted, nil
}

type recoveredRunnerDelete struct {
	repo string
	id   int64
	name string
}

// cleanupRecoveredRunnerRegistrations is shared by both runtime backends and
// deliberately runs even when no backend resources remain. That closes the
// registration-only debt case left by a crash after backend teardown. All
// repositories are listed and every candidate is classified before mutation.
func cleanupRecoveredRunnerRegistrations(
	ctx context.Context,
	scope string,
	configuredRepos []string,
	wantedNames map[string]bool,
	gh coldStartGitHub,
) error {
	repos := uniqueSorted(configuredRepos)
	toDelete := make([]recoveredRunnerDelete, 0)
	for _, repo := range repos {
		runners, _, err := gh.ListRunners(ctx, repo)
		if err != nil {
			return fmt.Errorf("cold-start: list runners for %s: %w", repo, err)
		}
		for _, runner := range runners {
			owned := runnerHasLabel(runner, orchestrator.JITOwnerLabel) &&
				runnerHasLabel(runner, orchestrator.JITScopeLabelPrefix+scope)
			if wantedNames[runner.Name] && !owned {
				return fmt.Errorf(
					"cold-start: recovered runner %q for %s lacks exact ownership labels",
					runner.Name, repo,
				)
			}
			if !owned {
				continue
			}
			if !validJITRunnerName(runner.Name) || runner.ID <= 0 {
				return fmt.Errorf(
					"cold-start: owned runner %q for %s has invalid identity",
					runner.Name, repo,
				)
			}
			if runner.Status != "offline" || runner.Busy {
				return fmt.Errorf(
					"cold-start: owned runner %q for %s is active (status=%s busy=%t)",
					runner.Name, repo, runner.Status, runner.Busy,
				)
			}
			toDelete = append(toDelete, recoveredRunnerDelete{
				repo: repo, id: runner.ID, name: runner.Name,
			})
		}
	}

	sort.Slice(toDelete, func(i, j int) bool {
		if toDelete[i].repo != toDelete[j].repo {
			return toDelete[i].repo < toDelete[j].repo
		}
		if toDelete[i].name != toDelete[j].name {
			return toDelete[i].name < toDelete[j].name
		}
		return toDelete[i].id < toDelete[j].id
	})
	for _, runner := range toDelete {
		if err := gh.DeleteRunner(ctx, runner.repo, runner.id); err != nil {
			return fmt.Errorf(
				"cold-start: delete runner %d for %s: %w",
				runner.id, runner.repo, err,
			)
		}
	}
	return nil
}

func runnerHasLabel(runner github.Runner, wanted string) bool {
	for _, label := range runner.Labels {
		if label.Name == wanted {
			return true
		}
	}
	return false
}

func validJITRunnerName(name string) bool {
	return strings.HasPrefix(name, "rs-") && strings.HasSuffix(name, "-runner") &&
		len(strings.TrimSuffix(strings.TrimPrefix(name, "rs-"), "-runner")) > 0
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
