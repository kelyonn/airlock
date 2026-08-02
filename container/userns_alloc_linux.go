//go:build linux

package container

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kelyonn/airlock/internal/filelock"
	"github.com/kelyonn/airlock/state"
)

// The persistence and locking half of UID-range allocation. Linux-only
// because Run — the sole caller — is; the range arithmetic and the
// free-slot search it wraps live in userns_alloc.go without a build tag so
// they stay testable on any platform.

// userNSState is the persisted state for UID-range allocation: a hint for
// where to start looking next, exactly like networkState.NextIP. It's only a
// hint — allocation cross-checks live containers for what's actually in use,
// so a stale or corrupt hint costs a few wasted probes, never a collision.
type userNSState struct {
	NextIndex int `json:"next_index"`
}

// userNSStatePath returns the path to the UID-range state file
// (~/.airlock/userns.json).
func userNSStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".airlock", "userns.json"), nil
}

// inUseUserNSIndexes returns the set of range indexes currently held by live
// containers, per state.List() — the same "cross-check reality, don't trust
// the counter" approach AllocateIP uses, and for the same reason: a
// persisted counter alone drifts out of sync with what's actually running
// the moment anything exits, crashes, or is cleaned up out from under it.
func inUseUserNSIndexes() (map[int]bool, error) {
	containers, err := state.List()
	if err != nil {
		return nil, err
	}
	inUse := make(map[int]bool, len(containers))
	for _, c := range containers {
		if c.UserNSBase == 0 {
			continue // not a --userns container
		}
		if idx, ok := userNSIndexForBase(c.UserNSBase); ok {
			inUse[idx] = true
		}
	}
	return inUse, nil
}

// allocateUserNSRange reserves a private host UID/GID range for one
// container and returns its base. The returned base is what the container's
// own UID 0 maps to; it owns [base, base+userNSIDRangeSize).
//
// There's no matching free function: a range is "held" for exactly as long
// as a live container in the state file records it, so state.Unregister —
// and state.List's own pruning of containers whose PIDs are gone — releases
// it implicitly. That also means a container killed with SIGKILL, or one
// whose airlock process died outright, doesn't strand its range the way an
// explicit release step would.
func allocateUserNSRange() (int, error) {
	path, err := userNSStatePath()
	if err != nil {
		return 0, fmt.Errorf("userns state path: %w", err)
	}

	var allocated int
	err = filelock.WithLock(path, func() error {
		inUse, err := inUseUserNSIndexes()
		if err != nil {
			return fmt.Errorf("determine in-use UID ranges: %w", err)
		}

		var us userNSState
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("read userns state: %w", err)
			}
			us.NextIndex = userNSFirstPrivateIndex
		} else if err := json.Unmarshal(data, &us); err != nil {
			return fmt.Errorf("parse userns state: %w", err)
		}

		idx, err := nextFreeUserNSIndex(us.NextIndex, inUse)
		if err != nil {
			return err
		}

		// Persist the hint one past what we just handed out. Between here
		// and state.Register recording it, this container's range exists
		// only as this advanced hint — the same window AllocateIP has, and
		// closed the same way: the next allocation starts looking after it
		// rather than handing out the identical value again.
		us.NextIndex = idx + 1
		if us.NextIndex > userNSMaxIndex {
			us.NextIndex = userNSFirstPrivateIndex
		}

		out, err := json.Marshal(us)
		if err != nil {
			return fmt.Errorf("marshal userns state: %w", err)
		}
		if err := os.WriteFile(path, out, 0644); err != nil {
			return fmt.Errorf("write userns state: %w", err)
		}

		allocated = userNSBaseForIndex(idx)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return allocated, nil
}
