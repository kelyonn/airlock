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

// Offsets into the seccomp_data struct passed to BPF programs by the kernel:
//
//	struct seccomp_data {
//	    int   nr;                    // offset 0
//	    __u32 arch;                  // offset 4
//	    __u64 instruction_pointer;   // offset 8
//	    __u64 args[6];               // offset 16
//	};
const (
	seccompDataNrOffset   = uint32(0)  // syscall number
	seccompDataArchOffset = uint32(4)  // architecture
	seccompDataArgsOffset = uint32(16) // start of args[6]
)

// seccompArgLow / seccompArgHigh give the offsets of the two 32-bit halves
// of the i'th syscall argument. BPF only loads 32 bits at a time, so a
// 64-bit argument has to be compared one word at a time; on the
// little-endian architectures airlock supports (amd64, arm64) the low word
// comes first.
func seccompArgLow(i int) uint32  { return seccompDataArgsOffset + uint32(i)*8 }
func seccompArgHigh(i int) uint32 { return seccompArgLow(i) + 4 }

// cloneNamespaceFlags is the set of clone(2) flags that create a NEW
// namespace: CLONE_NEWNS|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET (0x7c020000).
// Taken from the mask Docker's own default profile compares against, and
// verified against the individual CLONE_* constants rather than copied as an
// opaque number.
//
// A container's own process has no business creating further namespaces:
// airlock drops CAP_SYS_ADMIN (container/capabilities.go), so the kernel
// would refuse most of this anyway, but CLONE_NEWUSER specifically does NOT
// require CAP_SYS_ADMIN — an unprivileged process can create a user
// namespace and gain a full capability set inside it, which is the standard
// first step of several container escapes. Denying it here is defense in
// depth for exactly that.
//
// Nothing airlock itself does is affected: every namespace this container
// needed was created by the PARENT process's clone before this filter is
// ever installed (see container.go's Cloneflags), and the filter is
// installed last, immediately before exec'ing the user's command.
const cloneNamespaceFlags = uint32(0x7c020000)

// personalityAllowedValues is the exact set Docker's profile permits:
// PER_LINUX (0), PER_LINUX_32BIT (8), and the READ_IMPLIES_EXEC variants of
// each (0x20000, 0x20008), plus 0xffffffff — which is not a personality at
// all but the "query current personality without changing it" sentinel.
// Everything else (PER_BSD, PER_SVR4, the various emulation modes) stays
// denied: switching execution domain is a classic way to reach older, less
// scrutinized kernel compatibility paths.
var personalityAllowedValues = []uint32{
	0x00000000, // PER_LINUX
	0x00000008, // PER_LINUX32
	0x00020000, // PER_LINUX | ADDR_NO_RANDOMIZE-adjacent (READ_IMPLIES_EXEC)
	0x00020008, // PER_LINUX32 | READ_IMPLIES_EXEC
	0xffffffff, // query-only, changes nothing
}

// argFilteredSyscalls carries the numbers of the syscalls that need
// per-argument BPF comparison rather than a plain number match. The numbers
// come from the caller (the per-architecture ApplySeccomp) rather than being
// referenced directly here, so every unix.SYS_* reference stays in an
// architecture-specific file — this one is built for every Linux
// architecture, including ones that may not define a given constant at all.
type argFilteredSyscalls struct {
	clone       uint32
	personality uint32
}

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
func buildFilter(auditArch uint32, allowedSyscalls []uint32, cond argFilteredSyscalls) []unix.SockFilter {
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

	// Argument-conditional syscalls come after the flat matches above and
	// before the default branch below. Two things make that placement work:
	// the accumulator still holds the syscall number at this point (JEQ
	// doesn't modify it, only the LDs do), and each block below ends in its
	// own explicit RET on every path — so blocks never fall through into
	// one another with a stale accumulator, and no block needs to know where
	// any other block or the final default lives.
	filter = append(filter, appendArgFilteredBlock(cond.clone, cloneFilterBlock())...)
	filter = append(filter, appendArgFilteredBlock(cond.personality, personalityFilterBlock())...)

	filter = append(filter, bpfStmt(unix.BPF_RET|unix.BPF_K, seccompRetEPERM))
	return filter
}

// appendArgFilteredBlock prefixes a per-argument block with the test that
// selects it: if the syscall number doesn't match, jump clean over the whole
// block; if it does, fall into it.
func appendArgFilteredBlock(nr uint32, block []unix.SockFilter) []unix.SockFilter {
	out := make([]unix.SockFilter, 0, len(block)+1)
	out = append(out, bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, nr, 0, uint8(len(block))))
	return append(out, block...)
}

// cloneFilterBlock allows clone(2) only when none of the namespace-creation
// flags in cloneNamespaceFlags are set — Docker's SCMP_CMP_MASKED_EQ rule
// for the same syscall. Only the low word of the flags argument is examined,
// which is exact rather than a shortcut: the mask has no bits above 32, so
// the high word cannot affect the result.
//
// Entered with the accumulator holding the syscall number; every path ends
// in a RET, so nothing after it is reachable from here.
func cloneFilterBlock() []unix.SockFilter {
	return []unix.SockFilter{
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompArgLow(0)),
		bpfStmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, cloneNamespaceFlags),
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, seccompRetAllow),
		bpfStmt(unix.BPF_RET|unix.BPF_K, seccompRetEPERM),
	}
}

// personalityFilterBlock allows personality(2) only for the exact values in
// personalityAllowedValues. Unlike clone's mask test this is an equality
// test, so the high word genuinely matters: without checking it, a value
// like 0x1_00000000 would present a low word of 0 and be mistaken for
// PER_LINUX.
//
// Jump offsets are computed from the layout rather than hardcoded, so adding
// or removing an allowed value stays correct automatically:
//
//	[0]        load args[0] high word
//	[1]        if high != 0 -> EPERM
//	[2]        load args[0] low word
//	[3..3+n-1] one JEQ per allowed value -> ALLOW
//	[3+n]      EPERM (no value matched)
//	[3+n+1]    ALLOW
func personalityFilterBlock() []unix.SockFilter {
	n := len(personalityAllowedValues)
	idxEPERM := 3 + n
	idxAllow := idxEPERM + 1

	block := []unix.SockFilter{
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompArgHigh(0)),
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 0, uint8(idxEPERM-1-1)),
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompArgLow(0)),
	}
	for k, v := range personalityAllowedValues {
		here := 3 + k
		block = append(block, bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, v, uint8(idxAllow-here-1), 0))
	}
	block = append(block,
		bpfStmt(unix.BPF_RET|unix.BPF_K, seccompRetEPERM),
		bpfStmt(unix.BPF_RET|unix.BPF_K, seccompRetAllow),
	)
	return block
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
