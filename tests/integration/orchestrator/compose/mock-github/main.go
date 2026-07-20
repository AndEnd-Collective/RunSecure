// Mock GitHub API server for orchestrator integration tests.
//
// Endpoints:
//
//	GET    /repos/{owner}/{repo}                       → 200 (validation ping)
//	GET    /repos/{owner}/{repo}/actions/runs?status=queued|in_progress → workflow runs
//	GET    /repos/{owner}/{repo}/actions/runs/{id}/jobs?filter=latest → queued jobs
//	POST   /repos/{owner}/{repo}/actions/runners/generate-jitconfig → returns JIT config
//	GET    /repos/{owner}/{repo}/actions/runners/{id}  → online/busy runner
//	DELETE /repos/{owner}/{repo}/actions/runners/{id}  → 204
//
// Env vars:
//
//	MOCK_QUEUED_<OWNER>_<REPO>=N  → return that count
//	MOCK_AUTH_FAIL=1              → all responses 401
//	MOCK_JIT_FAIL=1               → /generate-jitconfig returns 422
//	MOCK_RATE_LIMIT=1             → 403 with X-RateLimit-Remaining: 0
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

var deletedRunners sync.Map

func main() {
	addr := envOr("MOCK_LISTEN", ":80")
	http.HandleFunc("/", handle)
	log.Printf("mock-github listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

var runnerIDSeq atomic.Int64

func handle(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("MOCK_AUTH_FAIL") == "1" {
		w.WriteHeader(401)
		return
	}
	if os.Getenv("MOCK_RATE_LIMIT") == "1" {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(403)
		return
	}

	switch {
	case strings.Contains(r.URL.Path, "/actions/runs/") && strings.HasSuffix(r.URL.Path, "/jobs"):
		jobsFor(w, r)
	case strings.HasSuffix(r.URL.Path, "/actions/runs"):
		runsFor(w, r)
	case strings.HasSuffix(r.URL.Path, "/generate-jitconfig"):
		generateJIT(w, r)
	case strings.Contains(r.URL.Path, "/actions/runners/") && r.Method == http.MethodDelete:
		deleteRunner(w, r)
	case strings.Contains(r.URL.Path, "/actions/runners/") && r.Method == http.MethodGet:
		getRunner(w, r)
	case r.Method == http.MethodGet:
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 1})
	default:
		w.WriteHeader(404)
	}
}

func runsFor(w http.ResponseWriter, r *http.Request) {
	n := queuedCount(r.URL.Path)
	runs := []map[string]any{}
	if n > 0 && r.URL.Query().Get("status") == "queued" && r.URL.Query().Get("page") == "1" {
		runs = append(runs, map[string]any{"id": 1})
	}
	setRateLimit(w)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
}

func jobsFor(w http.ResponseWriter, r *http.Request) {
	n := queuedCount(r.URL.Path)
	if r.URL.Query().Get("page") != "1" {
		n = 0
	}
	jobs := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		jobs = append(jobs, map[string]any{
			"id": i + 1, "name": fmt.Sprintf("mock-job-%d", i+1), "status": "queued",
			"labels": []string{"self-hosted", "Linux", "container"},
		})
	}
	setRateLimit(w)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs})
}

func queuedCount(path string) int {
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return 0
	}
	repo := strings.ToUpper(parts[2] + "_" + parts[3])
	repo = strings.ReplaceAll(repo, "-", "_")
	envKey := "MOCK_QUEUED_" + repo
	n := 0
	if v := os.Getenv(envKey); v != "" {
		fmt.Sscanf(v, "%d", &n)
	}
	return n
}

func setRateLimit(w http.ResponseWriter) {
	w.Header().Set("X-RateLimit-Limit", "5000")
	w.Header().Set("X-RateLimit-Remaining", "4999")
}

func generateJIT(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("MOCK_JIT_FAIL") == "1" {
		w.WriteHeader(422)
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	labels := []map[string]any{}
	if l, ok := body["labels"].([]any); ok {
		for _, x := range l {
			labels = append(labels, map[string]any{"name": x})
		}
	}
	id := runnerIDSeq.Add(1)
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"runner": map[string]any{
			"id":     id,
			"labels": labels,
		},
		"encoded_jit_config": "fake-b64-jit",
	})
}

func deleteRunner(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]
	deletedRunners.Store(id, true)
	w.WriteHeader(204)
}

func getRunner(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]
	if _, deleted := deletedRunners.Load(id); deleted {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var runnerID int64
	_, _ = fmt.Sscanf(id, "%d", &runnerID)
	setRateLimit(w)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": runnerID, "name": "mock-runsecure-runner", "status": "online", "busy": true,
	})
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
