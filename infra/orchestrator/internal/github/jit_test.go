package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateJITConfig_HappyPath(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/repos/o/r/actions/runners/generate-jitconfig", r.URL.Path)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "rs-r-spawn1", body["name"])
		labels := body["labels"].([]any)
		require.Contains(t, labels, "self-hosted")

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"runner":             map[string]any{"id": 42},
			"encoded_jit_config": "base64-blob",
		})
	})

	resp, err := c.GenerateJITConfig(context.Background(), "o/r", JITConfigRequest{
		Name:   "rs-r-spawn1",
		Labels: []string{"self-hosted", "Linux", "container"},
	})
	require.NoError(t, err)
	require.Equal(t, int64(42), resp.RunnerID)
	require.Equal(t, "base64-blob", resp.EncodedJITConfig)
}

func TestGenerateJITConfig_LabelMismatch_Rejected(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"runner": map[string]any{
				"id": 1,
				"labels": []map[string]any{
					{"name": "wrong-label"},
				},
			},
			"encoded_jit_config": "x",
		})
	})

	_, err := c.GenerateJITConfig(context.Background(), "o/r", JITConfigRequest{
		Name:   "rs-r-spawn1",
		Labels: []string{"requested-label"},
	})
	require.ErrorIs(t, err, ErrJITLabelMismatch)
}

func TestGenerateJITConfig_AuthFailed(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := c.GenerateJITConfig(context.Background(), "o/r", JITConfigRequest{Name: "n", Labels: []string{"l"}})
	require.ErrorIs(t, err, ErrAuthFailed)
}

func TestGenerateJITConfig_422NoSlot(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	})
	_, err := c.GenerateJITConfig(context.Background(), "o/r", JITConfigRequest{Name: "n", Labels: []string{"l"}})
	require.ErrorContains(t, err, "422")
}

func TestGenerateJITConfig_UnexpectedStatus(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := c.GenerateJITConfig(context.Background(), "o/r", JITConfigRequest{Name: "n", Labels: []string{"l"}})
	require.Error(t, err)
}

func TestGenerateJITConfig_MalformedJSON(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("not json"))
	})
	_, err := c.GenerateJITConfig(context.Background(), "o/r", JITConfigRequest{Name: "n", Labels: []string{"l"}})
	require.Error(t, err)
}

func TestDeleteRunner_HappyPath(t *testing.T) {
	called := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/repos/o/r/actions/runners/42", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.DeleteRunner(context.Background(), "o/r", 42))
	require.True(t, called)
}

func TestDeleteRunner_404IsNotError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	require.NoError(t, c.DeleteRunner(context.Background(), "o/r", 42))
}

func TestDeleteRunner_AuthFailed(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	require.ErrorIs(t, c.DeleteRunner(context.Background(), "o/r", 42), ErrAuthFailed)
}

func TestDeleteRunner_UnexpectedStatus(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	require.Error(t, c.DeleteRunner(context.Background(), "o/r", 42))
}
