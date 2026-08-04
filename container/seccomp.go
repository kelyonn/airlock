//go:build linux

package container

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Seccomp return values
const (
	seccompRetKill  = uint32(0x00000000) // kill the process
	seccompRetEPERM = uint32(0x00050001) // return EPERM (errno=1) to the caller
	seccompRetAllow = uint32(0x7fff0000) // allow the syscall
)

// Offsets into the seccomp_data struct passed to BPF programs by the kernel
const (
	seccompDataNrOffset   = uint32(0) // syscall number
	seccompDataArchOffset = uint32(4) // architecture
)

// seccompUnavailableMsg is printed when the environment doesn't support seccomp.
const seccompUnavailableMsg = "   ⚠️  Seccomp: skipped (not supported in this kernel/environment)"

// isLinuxtKitVM returns true when running inside Docker Desktop's linuxkit VM.
//
// In Docker Desktop (Mac/Windows), containers run inside a lightweight linuxkit
// VM. This VM's kernel uses RCU synchronization internally when installing
// seccomp filters (prctl(PR_SET_SECCOMP)), and because the VM typically has
// a single vCPU in debug/dev mode, synchronize_rcu() can deadlock the entire
// VM — freezing ALL goroutines in the process, including timers and signal
// handlers. Detecting linuxkit allows us to skip the frozen-kernel path safely.
//
// On production Linux systems (bare metal, EC2, GCP, etc.) this returns false
// and seccomp is installed normally.
func isLinuxtKitVM() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "linuxkit")
}

// bpfStmt creates a no-jump BPF instruction.
func bpfStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

// bpfJump creates a conditional-jump BPF instruction.
func bpfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// buildFilter assembles the BPF program for a given architecture audit value
// and set of blocked syscall numbers:
//
//	[0]  Load arch field from seccomp_data
//	[1]  If arch == auditArch: skip [2]; else fall through to [2]
//	[2]  KILL (wrong architecture — reject unknown arch binaries)
//	[3]  Load syscall number
//	[4…] Per-syscall: JEQ allowedNR → ALLOW
//	[N]  Default: EPERM
//
// An allow-list rather than the deny-list this used to be: default-deny
// means a syscall airlock's own list is simply missing from — not one
// anybody deliberately decided to block — fails closed instead of silently
// through. allowedSyscalls (seccomp_linux_{amd64,arm64}.go) is sized in the
// hundreds rather than the single digits accordingly; see its own doc
// comment for where that list actually comes from.
func buildFilter(auditArch uint32, allowedSyscalls []uint32) []unix.SockFilter {
	filter := []unix.SockFilter{
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataArchOffset),
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, auditArch, 1, 0),
		bpfStmt(unix.BPF_RET|unix.BPF_K, seccompRetKill),
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataNrOffset),
	}
	for _, nr := range allowedSyscalls {
		filter = append(filter,
			bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, nr, 0, 1),
			bpfStmt(unix.BPF_RET|unix.BPF_K, seccompRetAllow),
		)
	}
	filter = append(filter, bpfStmt(unix.BPF_RET|unix.BPF_K, seccompRetEPERM))
	return filter
}

// installFilter installs a fully-assembled BPF program as this thread's
// seccomp filter. It is architecture-independent; callers assemble the
// filter with buildFilter using their architecture's AUDIT_ARCH value and
// blocked syscall table.
func installFilter(filter []unix.SockFilter) error {
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	// PR_SET_NO_NEW_PRIVS: required before installing a seccomp filter as a
	// non-root process (or when the caller lacks CAP_SYS_ADMIN). It prevents
	// execve'd children from gaining new privileges via setuid/setcap binaries.
	// Once set it is irrevocable for this process and all its descendants.
	if _, _, errno := unix.Syscall6(
		unix.SYS_PRCTL,
		38, // PR_SET_NO_NEW_PRIVS
		1, 0, 0, 0, 0,
	); errno != 0 {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", errno)
	}

	// prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog): install the BPF filter
	// on THIS THREAD. After syscall.Exec replaces the process image, the
	// execve'd binary inherits the filter (the kernel carries it forward).
	if _, _, errno := unix.Syscall6(
		unix.SYS_PRCTL,
		unix.PR_SET_SECCOMP,
		unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&prog)),
		0, 0, 0,
	); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_SECCOMP): %w", errno)
	}

	return nil
}
