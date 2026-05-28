// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher watches files for changes and triggers callbacks.
type Watcher struct {
	fsWatcher    *fsnotify.Watcher
	callback     func(path string)
	debounce     time.Duration
	stopChan     chan struct{}
	pending      map[string]time.Time
	pendingMutex sync.Mutex
	validExts    []string
}

// New creates a new file watcher.
func New(debounce time.Duration, callback func(path string)) (*Watcher, error) {
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &Watcher{
		fsWatcher: fsWatcher,
		callback:  callback,
		debounce:  debounce,
		stopChan:  make(chan struct{}),
		pending:   make(map[string]time.Time),
		validExts: []string{".json", ".yaml", ".yml"},
	}, nil
}

// AddPath adds a path (file or directory) to watch.
func (w *Watcher) AddPath(path string) error {
	return w.fsWatcher.Add(path)
}

// AddRecursive adds a directory and all subdirectories to watch.
func (w *Watcher) AddRecursive(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Only watch directories, fsnotify will catch file changes in them
		if info.IsDir() {
			return w.AddPath(path)
		}
		return nil
	})
}

// Start begins watching for changes.
func (w *Watcher) Start() {
	go w.processEvents()
	go w.processDebounced()
}

// Stop stops the watcher.
func (w *Watcher) Stop() error {
	close(w.stopChan)
	return w.fsWatcher.Close()
}

// processEvents reads events from fsnotify and adds them to pending.
func (w *Watcher) processEvents() {
	for {
		select {
		case <-w.stopChan:
			return
		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}
			// Only care about Write and Create events
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			// Only process files with valid extensions
			if !w.isValidFile(event.Name) {
				continue
			}
			w.pendingMutex.Lock()
			w.pending[event.Name] = time.Now()
			w.pendingMutex.Unlock()
		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			// Log error but continue watching
			_ = err // In production, this could be logged
		}
	}
}

// processDebounced processes pending events after debounce period.
func (w *Watcher) processDebounced() {
	ticker := time.NewTicker(w.debounce / 2)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			w.pendingMutex.Lock()
			now := time.Now()
			var toProcess []string
			for path, timestamp := range w.pending {
				if now.Sub(timestamp) >= w.debounce {
					toProcess = append(toProcess, path)
					delete(w.pending, path)
				}
			}
			w.pendingMutex.Unlock()

			for _, path := range toProcess {
				w.callback(path)
			}
		}
	}
}

// isValidFile checks if the file has a valid extension.
func (w *Watcher) isValidFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, validExt := range w.validExts {
		if ext == validExt {
			return true
		}
	}
	return false
}
