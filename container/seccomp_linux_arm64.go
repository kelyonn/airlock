//go:build linux && arm64

package container

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// auditArch is the AUDIT_ARCH value for aarch64
// (EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE).
//
// This was previously hardcoded to the x86_64 value in a single shared
// seccomp.go, which meant every syscall's architecture check failed on
// arm64 and the filter's default-deny KILL branch fired on the very first
// syscall — every container was killed instantly on arm64 hosts (Graviton,
// Apple Silicon Linux VMs, Raspberry Pi, etc). Splitting the filter per
// architecture fixes that.
const auditArch = uint32(0xc00000b7)

// blockedSyscalls is the curated list of syscalls blocked inside airlock
// containers on arm64. Note SYS_MKNOD is intentionally absent: arm64 has no
// mknod(2) syscall number at all (only mknodat), so only SYS_MKNODAT needs
// to be listed.
var blockedSyscalls = []uint32{
	unix.SYS_REBOOT,          // reboot the host
	unix.SYS_KEXEC_LOAD,      // load a new kernel image
	unix.SYS_SWAPON,          // enable a swap device
	unix.SYS_SWAPOFF,         // disable a swap device
	unix.SYS_MOUNT,           // remount host filesystems
	unix.SYS_PIVOT_ROOT,      // escape the container root
	unix.SYS_SETTIMEOFDAY,    // manipulate the host clock
	unix.SYS_PERF_EVENT_OPEN, // open perf events (side-channel attacks)
	unix.SYS_MKNODAT,         // create device nodes (dirfd-relative)
}

// ApplySeccomp installs a pure-Go BPF seccomp filter that blocks a curated
// set of dangerous syscalls from within the container. See the amd64
// variant's doc comment for the linuxkit VM detection rationale.
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
