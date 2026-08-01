// Package filelock provides simple advisory file locking used to serialize
// concurrent access to JSON state files shared by multiple airlock
// processes — e.g. several containers in a compose stack starting at once
// and each registering themselves in containers.json / network.json.
package filelock

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WithLock acquires an exclusive flock on "<path>.lock" (creating the lock
// file and its parent directory if needed), runs fn while holding the
// lock, and releases it before returning. It never touches path itself —
// callers read/modify/write that file from inside fn.
//
// A dedicated lock file (rather than flock'ing the state file directly) is
// deliberate: it means readers of the state file are never blocked by an
// open exclusive lock on the file they're trying to read, only writers that
// go through WithLock contend with each other.
func WithLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create lock dir: %w", err)
	}

	lockPath := path + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer lf.Close()

	// LOCK_EX blocks until the lock is available.
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire lock %s: %w", lockPath, err)
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) // nolint:errcheck

	return fn()
}
