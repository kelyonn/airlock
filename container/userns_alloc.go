// No build tag — the UID-range arithmetic and free-slot search below are
// pure logic, kept separate from the locking/persistence that wraps them
// (userns_alloc_linux.go) so they're testable on any platform, the same
// reason parseMemoryLimit and ExitError live outside the Linux-only files.

package container

import "fmt"

// userNSHostIDOffset / userNSIDRangeSize define the host UID/GID range a
// --userns container's own 0-65535 range is mapped onto. 100000 is the same
// convention most distros' subuid/subgid defaults and other container tools
// use, chosen simply to stay clear of real system accounts (which end well
// before 100000 on virtually every distro); 65536 per container matches the
// per-user block size /etc/subuid hands out by default.
//
// Ranges are handed out by index: index N covers
// [userNSHostIDOffset + N*userNSIDRangeSize, +userNSIDRangeSize). Index 0 is
// reserved (see userNSSharedIndex); private per-container ranges start at
// userNSFirstPrivateIndex.
const (
	userNSHostIDOffset = 100000
	userNSIDRangeSize  = 65536

	// userNSSharedIndex is the range every --userns container used to get,
	// unconditionally. It's still what a container falls back to when its
	// rootfs is NOT private to it (overlayfs unavailable, so it runs
	// directly against the shared image cache — see SetupOverlay and Run's
	// handling of it). Such containers must all agree on one UID, because
	// they're chowning the same directory tree: handing them distinct
	// ranges would mean the second container to start re-chowns the first
	// one's running rootfs out from under it. Sharing a UID means sharing
	// an identity, which is exactly the isolation gap private ranges close
	// — so this is a real, if narrow, degraded mode, reported as such.
	userNSSharedIndex = 0

	// userNSFirstPrivateIndex is the lowest index handed out per-container,
	// deliberately 1 rather than 0 so a container with a private rootfs
	// never shares an identity with the shared-fallback range above.
	userNSFirstPrivateIndex = 1

	// userNSMaxIndex bounds how many distinct ranges can be live at once.
	// 1024 concurrent --userns containers is far past anything airlock is
	// built for, and keeps the top of the range (~67.3M) an order of
	// magnitude below the 2^31 boundary where 32-bit UID handling starts
	// getting quietly inconsistent across tools.
	userNSMaxIndex = 1024
)

// userNSBaseForIndex returns the first host UID/GID of range index i.
func userNSBaseForIndex(i int) int {
	return userNSHostIDOffset + i*userNSIDRangeSize
}

// userNSIndexForBase is the inverse of userNSBaseForIndex, reporting false
// for any base that isn't a valid range start (an entry written by a
// different airlock version, or a hand-edited state file).
func userNSIndexForBase(base int) (int, bool) {
	if base < userNSHostIDOffset {
		return 0, false
	}
	delta := base - userNSHostIDOffset
	if delta%userNSIDRangeSize != 0 {
		return 0, false
	}
	return delta / userNSIDRangeSize, true
}

// nextFreeUserNSIndex walks forward from hint, wrapping once, for the first
// private range index not present in inUse (keyed by index). Split out from
// the locking and file I/O around it so the search itself can be tested
// directly.
func nextFreeUserNSIndex(hint int, inUse map[int]bool) (int, error) {
	if hint < userNSFirstPrivateIndex || hint > userNSMaxIndex {
		hint = userNSFirstPrivateIndex
	}

	candidate := hint
	start := candidate
	for inUse[candidate] {
		candidate++
		if candidate > userNSMaxIndex {
			candidate = userNSFirstPrivateIndex
		}
		if candidate == start {
			return 0, fmt.Errorf("no free user-namespace UID ranges left (all %d in use)",
				userNSMaxIndex-userNSFirstPrivateIndex+1)
		}
	}
	return candidate, nil
}
