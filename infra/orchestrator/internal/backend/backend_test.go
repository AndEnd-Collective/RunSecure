package backend

import (
	"context"
	"testing"
	"time"
)

type fakeBackend struct{}

func (fakeBackend) Spawn(context.Context, SpawnInput) (Handle, error)        { return Handle{}, nil }
func (fakeBackend) WaitForExit(context.Context, Handle, time.Duration) (int, bool) { return 0, false }
func (fakeBackend) Teardown(context.Context, Handle, bool) error             { return nil }
func (fakeBackend) Reconcile(context.Context, string) ([]Handle, error)      { return nil, nil }
func (fakeBackend) Name() string                                            { return "fake" }

var _ Backend = fakeBackend{}

func TestSpawnInputFields(t *testing.T) {
	input := SpawnInput{
		Scope:  "s",
		Labels: []string{"a"},
	}

	if input.Scope != "s" {
		t.Errorf("expected Scope='s', got %q", input.Scope)
	}

	if len(input.Labels) != 1 || input.Labels[0] != "a" {
		t.Errorf("expected Labels=['a'], got %v", input.Labels)
	}

	handle := Handle{
		Refs: map[string]string{"runner": "x"},
	}

	if handle.Refs["runner"] != "x" {
		t.Errorf("expected Refs['runner']='x', got %q", handle.Refs["runner"])
	}
}
