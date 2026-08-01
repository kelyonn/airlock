//go:build linux && amd64

package container

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// auditArchX86_64 is the AUDIT_ARCH value for x86_64
// (EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE).
const auditArch = uint32(0xc000003e)

// blockedSyscalls is the curated list of syscalls blocked inside airlock
// containers on x86_64. SYS_MKNOD is included here because it exists as a
// distinct syscall number on this architecture (arm64 only has mknodat);
// blocking it stops containers from creating new device nodes after we've
// set up the minimal /dev.
var blockedSyscalls = []uint32{
	unix.SYS_REBOOT,          // reboot the host
	unix.SYS_KEXEC_LOAD,      // load a new kernel image
	unix.SYS_SWAPON,          // enable a swap device
	unix.SYS_SWAPOFF,         // disable a swap device
	unix.SYS_MOUNT,           // remount host filesystems
	unix.SYS_PIVOT_ROOT,      // escape the container root
	unix.SYS_SETTIMEOFDAY,    // manipulate the host clock
	unix.SYS_PERF_EVENT_OPEN, // open perf events (side-channel attacks)
	unix.SYS_MKNOD,           // create device nodes
	unix.SYS_MKNODAT,         // create device nodes (dirfd-relative)
}

// ApplySeccomp installs a pure-Go BPF seccomp filter that blocks a curated
// set of dangerous syscalls from within the container.
//
// Environments where seccomp is not installed (returned early):
//   - Docker Desktop / linuxkit VM: prctl(PR_SET_SECCOMP) triggers a kernel
//     RCU synchronization deadlock on single-vCPU VMs. We detect linuxkit and
//     skip gracefully rather than hanging indefinitely.
//   - Any environment where PR_SET_NO_NEW_PRIVS or PR_SET_SECCOMP returns an
//     error (e.g., some hardened CI that blocks nested seccomp) — we log a
//     warning and continue.
func ApplySeccomp() error {
	if isLinuxtKitVM() {
		fmt.Fprintf(os.Stderr, "%s\n", seccompUnavailableMsg)
		return nil
	}

	filter := buildFilter(auditArch, blockedSyscalls)
	if err := installFilter(filter); err != nil {
		return err
	}

	if Verbose {
		fmt.Printf("   🔐 Seccomp: blocking %d dangerous syscalls\n", len(blockedSyscalls))
	}
	return nil
}
