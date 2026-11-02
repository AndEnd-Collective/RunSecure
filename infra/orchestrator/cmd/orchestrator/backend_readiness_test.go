package main

import (
	"context"
	"errors"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/stretchr/testify/require"
	"testing"
)

type boundedReadyBackend struct{ backend.Backend }

func (boundedReadyBackend) Ready(context.Context, string) error { return errors.New("bounded probe") }

type reconcileReadyBackend struct{ backend.Backend }

func (reconcileReadyBackend) Reconcile(context.Context, string) ([]backend.Handle, error) {
	return nil, errors.New("legacy probe")
}

func TestBackendReadinessUsesBoundedProbeWithLegacyFallback(t *testing.T) {
	require.EqualError(t, checkBackendReady(context.Background(), boundedReadyBackend{}, "scope"), "bounded probe")
	require.EqualError(t, checkBackendReady(context.Background(), reconcileReadyBackend{}, "scope"), "legacy probe")
}
