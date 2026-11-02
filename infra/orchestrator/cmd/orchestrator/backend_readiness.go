package main

import (
	"context"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
)

func checkBackendReady(ctx context.Context, be backend.Backend, scope string) error {
	if probe, ok := be.(interface {
		Ready(context.Context, string) error
	}); ok {
		return probe.Ready(ctx, scope)
	}
	_, err := be.Reconcile(ctx, scope)
	return err
}
