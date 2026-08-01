//go:build linux

package container

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// allowedCapabilities is the minimal set of capabilities left in a
// container's bounding set — Docker's actual default allowlist (CHOWN,
// DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID, SETPCAP,
// NET_BIND_SERVICE, NET_RAW, SETFCAP, SYS_CHROOT, MKNOD, AUDIT_WRITE).
//
// CAP_NET_RAW and CAP_MKNOD are worth calling out explicitly since they're
// easy to assume belong on the "obviously drop this" pile alongside
// CAP_SYS_ADMIN: they don't, in Docker's real default. Dropping CAP_NET_RAW
// silently breaks ping(8) in every container (busybox/iputils ping needs a
// raw ICMP socket) — exactly the kind of basic connectivity check compose
// stacks and entrypoint scripts lean on, and airlock's own E2E suite tests
// it. CAP_MKNOD is kept for the same reason: Docker images may legitimately
// mknod inside their own tmpfs-backed /dev at startup. Both are still
// meaningfully fenced in by seccomp (SYS_MKNOD/SYS_MKNODAT are blocked
// outright — see seccomp_linux_*.go) and by not being real root's-eye-view
// of the host (no bind-mounted host /dev, see devices.go).
//
// Every other capability is dropped, notably CAP_SYS_ADMIN (the "root
// inside a namespace" catch-all), CAP_SYS_MODULE, CAP_SYS_RAWIO,
// CAP_SYS_BOOT, CAP_NET_ADMIN, and CAP_SYS_PTRACE.
var allowedCapabilities = []uintptr{
	unix.CAP_CHOWN,
	unix.CAP_DAC_OVERRIDE,
	unix.CAP_FOWNER,
	unix.CAP_FSETID,
	unix.CAP_KILL,
	unix.CAP_SETGID,
	unix.CAP_SETUID,
	unix.CAP_SETPCAP,
	unix.CAP_NET_BIND_SERVICE,
	unix.CAP_NET_RAW,
	unix.CAP_SETFCAP,
	unix.CAP_SYS_CHROOT,
	unix.CAP_MKNOD,
	unix.CAP_AUDIT_WRITE,
}

// linuxCapHeader / linuxCapData mirror struct cap_user_header_t / struct
// cap_user_data_t from <linux/capability.h>. Two data words are required
// because Linux's capability bitmask (currently up to CAP_LAST_CAP, in the
// high 30s/low 40s) does not fit in a single 32-bit word.
type linuxCapHeader struct {
	version uint32
	pid     int32
}

type linuxCapData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

const linuxCapVersion3 = 0x20080522 // _LINUX_CAPABILITY_VERSION_3

// DropCapabilities restricts the process — and everything it execs from
// here on — to allowedCapabilities.
//
// Two mechanisms are used together; they are not redundant:
//
//  1. PR_CAPBSET_DROP removes capabilities from the bounding set, one at a
//     time (the kernel offers no bitmask form for this).
//  2. capset(2) narrows this process's own effective/permitted/inheritable
//     sets immediately.
//
// The bounding set is the one that actually matters for a container
// runtime like this one. Airlock runs the container's init process as the
// real host UID 0 with no user namespace, and per the kernel's execve(2)
// legacy root-compatibility rule, a UID-0 process exec'ing a binary with no
// file capabilities has its permitted+effective sets RE-EXPANDED to the
// full bounding set on every exec — so whatever capset() narrows here would
// otherwise be silently undone the moment syscall.Exec runs in namespaces.go.
// The bounding set has no such exception: it's a hard ceiling the kernel
// enforces on every future exec in this process tree, which is what makes
// it the lever that actually survives exec for a root container.
//
// This is not a substitute for user namespaces (see the --userns flag) —
// a process with CAP_SYS_ADMIN-adjacent capabilities removed is still real
// root from the host's point of view for anything capability checks don't
// gate (e.g. DAC is already satisfied by UID 0). It closes off a specific,
// well-understood set of host-affecting syscalls.
func DropCapabilities() error {
	// 1. Narrow the bounding set — the part that actually persists across
	// the upcoming exec.
	for c := uintptr(0); c <= unix.CAP_LAST_CAP; c++ {
		if capabilityAllowed(c) {
			continue
		}
		// PR_CAPBSET_DROP returns EINVAL for capability numbers the running
		// kernel doesn't recognize (e.g. built against a newer CAP_LAST_CAP
		// than an older host kernel supports) — ignore those, there's
		// nothing to drop.
		if _, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, c, 0); errno != 0 && errno != unix.EINVAL {
			return fmt.Errorf("PR_CAPBSET_DROP(%d): %w", c, errno)
		}
	}

	// 2. Narrow this process's own effective/permitted/inheritable sets too,
	// for defense in depth against anything airlock itself does between here
	// and exec. (Belt-and-braces: exec will re-derive from the now-narrower
	// bounding set regardless of what this step does.)
	var mask uint32
	for _, c := range allowedCapabilities {
		mask |= 1 << uint(c)
	}

	header := linuxCapHeader{version: linuxCapVersion3, pid: 0}
	data := [2]linuxCapData{
		{effective: mask, permitted: mask, inheritable: mask},
		{}, // capabilities 32-63 — none of ours fall in this word
	}

	if _, _, errno := unix.Syscall(unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return fmt.Errorf("capset: %w", errno)
	}

	return nil
}

func capabilityAllowed(c uintptr) bool {
	for _, allowed := range allowedCapabilities {
		if allowed == c {
			return true
		}
	}
	return false
}
