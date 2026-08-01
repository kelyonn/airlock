//go:build linux

package container

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// resolvedUser is what a USER spec resolves to: numeric uid/gid, plus
// whatever home directory /etc/passwd lists (falling back to "/" if
// unresolvable), so HOME can be set correctly for a non-root user.
type resolvedUser struct {
	UID  int
	GID  int
	Home string
}

// ApplyUser switches the calling process's real/effective/saved UID and GID
// according to spec, which may be:
//
//	""             no-op — stay as whatever we already are (root)
//	"uid"          numeric UID; primary GID resolved from /etc/passwd if
//	               the image has an entry for it, else 0
//	"uid:gid"      numeric UID and GID, no /etc/passwd lookup needed
//	"name"         looked up in /etc/passwd for UID and primary GID
//	"name:group"   name looked up in /etc/passwd for UID, group looked up
//	               in /etc/group for GID
//
// Returns the resolved user's home directory (empty string if spec is
// empty) — the caller uses this to set HOME correctly, since the exec
// environment here is an explicit envp built by hand rather than the
// process's actual environment, so an os.Setenv call in this function
// would have no effect on what the exec'd program actually sees.
//
// Must run AFTER the capability bounding set has already been narrowed
// (DropCapabilities) and BEFORE exec: dropping to a non-root UID clears the
// process's effective/permitted capability sets as a kernel security
// measure — which is exactly the point. A non-root container process ends
// up with no capabilities at all, the same as any other non-root Linux
// process, regardless of what the (already-narrowed) bounding set allows.
//
// /etc/passwd and /etc/group are read from the CURRENT root, so this must
// be called after pivot_root — otherwise it would resolve against the
// host's users, not the image's.
func ApplyUser(spec string) (home string, err error) {
	if spec == "" {
		return "", nil
	}

	ru, err := resolveUser(spec)
	if err != nil {
		return "", err
	}

	// Supplementary groups, then primary group, then UID last — the
	// standard privilege-drop order. UID has to go last: once it's no
	// longer 0, the capabilities needed to change GID may already be gone.
	if err := unix.Setgroups([]int{ru.GID}); err != nil {
		return "", fmt.Errorf("setgroups: %w", err)
	}
	if err := unix.Setresgid(ru.GID, ru.GID, ru.GID); err != nil {
		return "", fmt.Errorf("setresgid: %w", err)
	}
	if err := unix.Setresuid(ru.UID, ru.UID, ru.UID); err != nil {
		return "", fmt.Errorf("setresuid: %w", err)
	}

	return ru.Home, nil
}

// resolveUser parses a "user[:group]" spec and resolves both halves
// against /etc/passwd and /etc/group.
func resolveUser(spec string) (resolvedUser, error) {
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")

	uid, gid, home, err := lookupPasswdEntry(userPart)
	if err != nil {
		return resolvedUser{}, err
	}

	if hasGroup {
		g, gerr := lookupGroupEntry(groupPart)
		if gerr != nil {
			return resolvedUser{}, gerr
		}
		gid = g
	}

	return resolvedUser{UID: uid, GID: gid, Home: home}, nil
}

// lookupPasswdEntry resolves userPart (a name or a numeric UID string)
// against /etc/passwd. A numeric userPart is always accepted even without a
// matching /etc/passwd entry — many minimal images have no /etc/passwd at
// all, and Docker's own USER directive allows a bare numeric UID in exactly
// that case.
func lookupPasswdEntry(userPart string) (uid, gid int, home string, err error) {
	numericUID, isNumeric := -1, false
	if n, nerr := strconv.Atoi(userPart); nerr == nil {
		numericUID, isNumeric = n, true
	}

	f, ferr := os.Open("/etc/passwd")
	if ferr == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) < 6 {
				continue
			}
			fUID, uerr := strconv.Atoi(fields[2])
			if uerr != nil {
				continue
			}
			matches := (isNumeric && fUID == numericUID) || (!isNumeric && fields[0] == userPart)
			if !matches {
				continue
			}
			fGID, _ := strconv.Atoi(fields[3])
			return fUID, fGID, fields[5], nil
		}
	}

	if isNumeric {
		// No /etc/passwd, or no matching entry — a bare numeric UID is
		// still valid; default GID 0, default HOME "/".
		return numericUID, 0, "/", nil
	}
	return 0, 0, "", fmt.Errorf("no such user in image: %q", userPart)
}

// lookupGroupEntry resolves a group name (or numeric GID string) against
// /etc/group.
func lookupGroupEntry(groupPart string) (int, error) {
	if n, err := strconv.Atoi(groupPart); err == nil {
		return n, nil
	}

	f, err := os.Open("/etc/group")
	if err != nil {
		return 0, fmt.Errorf("resolve group %q: open /etc/group: %w", groupPart, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[0] == groupPart {
			gid, gerr := strconv.Atoi(fields[2])
			if gerr != nil {
				return 0, fmt.Errorf("resolve group %q: malformed gid in /etc/group", groupPart)
			}
			return gid, nil
		}
	}
	return 0, fmt.Errorf("no such group in image: %q", groupPart)
}
