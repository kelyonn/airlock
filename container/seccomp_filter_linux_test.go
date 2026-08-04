//go:build linux

package container

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The BPF blocks for clone/personality are hand-assembled with relative jump
// offsets, where an off-by-one doesn't produce a compile error or an obvious
// crash — it silently sends a syscall to the wrong RET, which means either a
// container that mysteriously can't start or, worse, a filter that quietly
// permits what it was written to deny. These tests interpret the generated
// programs the way the kernel does, so the offsets are checked by execution
// rather than by reading them.

// runFilter is a minimal interpreter for the subset of classic BPF that
// buildFilter emits: absolute word loads, immediate AND, immediate JEQ, and
// RET. It returns the seccomp action the program settles on for the given
// syscall number and first argument.
func runFilter(t *testing.T, prog []unix.SockFilter, arch, nr uint32, arg0 uint64) uint32 {
	t.Helper()

	load := func(off uint32) uint32 {
		switch off {
		case seccompDataNrOffset:
			return nr
		case seccompDataArchOffset:
			return arch
		case seccompArgLow(0):
			return uint32(arg0)
		case seccompArgHigh(0):
			return uint32(arg0 >> 32)
		default:
			t.Fatalf("filter loaded an unexpected seccomp_data offset %d", off)
			return 0
		}
	}

	var acc uint32
	for pc := 0; pc < len(prog); {
		if pc >= len(prog) {
			t.Fatal("program ran off the end without returning")
		}
		ins := prog[pc]
		switch ins.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			acc = load(ins.K)
			pc++
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			acc &= ins.K
			pc++
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if acc == ins.K {
				pc += 1 + int(ins.Jt)
			} else {
				pc += 1 + int(ins.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return ins.K
		default:
			t.Fatalf("unexpected BPF opcode 0x%x at pc=%d", ins.Code, pc)
		}
	}
	t.Fatal("program ran off the end without returning")
	return 0
}

const (
	testArch  = uint32(0xc000003e)
	testClone = uint32(56)
	testPers  = uint32(135)
	testRead  = uint32(0)
	testMount = uint32(165)
)

func testFilter(t *testing.T) []unix.SockFilter {
	t.Helper()
	return buildFilter(testArch, []uint32{testRead}, argFilteredSyscalls{
		clone:       testClone,
		personality: testPers,
	})
}

func TestFilterPlainAllowAndDefaultDeny(t *testing.T) {
	prog := testFilter(t)

	if got := runFilter(t, prog, testArch, testRead, 0); got != seccompRetAllow {
		t.Errorf("allow-listed syscall: got 0x%x, want ALLOW (0x%x)", got, seccompRetAllow)
	}
	// A syscall that's on no list at all must hit the default branch. mount
	// is a deliberate choice: it's one airlock specifically intends to deny.
	if got := runFilter(t, prog, testArch, testMount, 0); got != seccompRetEPERM {
		t.Errorf("unlisted syscall: got 0x%x, want EPERM (0x%x)", got, seccompRetEPERM)
	}
	// Wrong architecture must KILL, not merely deny — a mismatched arch means
	// the syscall numbers themselves can't be trusted.
	if got := runFilter(t, prog, testArch^0xffff, testRead, 0); got != seccompRetKill {
		t.Errorf("wrong arch: got 0x%x, want KILL (0x%x)", got, seccompRetKill)
	}
}

func TestFilterCloneNamespaceFlags(t *testing.T) {
	prog := testFilter(t)

	cases := []struct {
		name  string
		flags uint64
		want  uint32
	}{
		// What fork(), pthread_create() and Go's own runtime actually pass.
		{name: "plain fork (SIGCHLD only)", flags: 0x11, want: seccompRetAllow},
		{name: "thread creation", flags: 0x3d0f00, want: seccompRetAllow},
		{name: "no flags at all", flags: 0, want: seccompRetAllow},

		// Each namespace flag individually must be refused.
		{name: "CLONE_NEWUSER", flags: 0x10000000, want: seccompRetEPERM},
		{name: "CLONE_NEWNS", flags: 0x00020000, want: seccompRetEPERM},
		{name: "CLONE_NEWPID", flags: 0x20000000, want: seccompRetEPERM},
		{name: "CLONE_NEWNET", flags: 0x40000000, want: seccompRetEPERM},
		{name: "CLONE_NEWUTS", flags: 0x04000000, want: seccompRetEPERM},
		{name: "CLONE_NEWIPC", flags: 0x08000000, want: seccompRetEPERM},

		// Namespace flags hidden among legitimate ones are still refused.
		{name: "CLONE_NEWUSER smuggled with thread flags", flags: 0x3d0f00 | 0x10000000, want: seccompRetEPERM},

		// High bits are irrelevant to a mask with no high bits set — this
		// documents that the low-word-only comparison is exact, not a shortcut.
		{name: "high bits set, no namespace flags", flags: 0xffffffff00000011, want: seccompRetAllow},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runFilter(t, prog, testArch, testClone, tc.flags); got != tc.want {
				t.Errorf("clone(0x%x): got 0x%x, want 0x%x", tc.flags, got, tc.want)
			}
		})
	}
}

func TestFilterPersonality(t *testing.T) {
	prog := testFilter(t)

	for _, v := range personalityAllowedValues {
		if got := runFilter(t, prog, testArch, testPers, uint64(v)); got != seccompRetAllow {
			t.Errorf("personality(0x%x): got 0x%x, want ALLOW", v, got)
		}
	}

	denied := []uint64{
		0x1,        // PER_SVR4-ish, not in the allowed set
		0x9,        // arbitrary nearby value
		0x20009,    // one bit off an allowed value
		0xfffffffe, // one below the query sentinel
	}
	for _, v := range denied {
		if got := runFilter(t, prog, testArch, testPers, v); got != seccompRetEPERM {
			t.Errorf("personality(0x%x): got 0x%x, want EPERM", v, got)
		}
	}

	// The reason personality checks the high word at all: without it, this
	// would present a low word of 0 and be mistaken for PER_LINUX.
	if got := runFilter(t, prog, testArch, testPers, 0x1_00000000); got != seccompRetEPERM {
		t.Errorf("personality(0x100000000): got 0x%x, want EPERM — high word must be checked", got)
	}
}

// TestFilterFitsKernelLimit guards a hard cap that the real allow-lists get
// genuinely close to: the kernel rejects any filter longer than
// BPF_MAXINSNS (4096) outright, and each allow-listed syscall costs two
// instructions.
func TestFilterFitsKernelLimit(t *testing.T) {
	const bpfMaxInsns = 4096
	prog := buildFilter(auditArch, allowedSyscalls, argFilteredSyscalls{
		clone:       unix.SYS_CLONE,
		personality: unix.SYS_PERSONALITY,
	})
	if len(prog) > bpfMaxInsns {
		t.Fatalf("filter is %d instructions, over the kernel's %d limit", len(prog), bpfMaxInsns)
	}
	t.Logf("filter is %d instructions (%d syscalls allow-listed)", len(prog), len(allowedSyscalls))
}

// TestRealFilterDeniesEscapeClone runs the ACTUAL per-architecture
// allow-list, not a synthetic one, against the flags a container escape
// would use.
func TestRealFilterDeniesEscapeClone(t *testing.T) {
	prog := buildFilter(auditArch, allowedSyscalls, argFilteredSyscalls{
		clone:       unix.SYS_CLONE,
		personality: unix.SYS_PERSONALITY,
	})

	if got := runFilter(t, prog, auditArch, unix.SYS_CLONE, 0x10000000); got != seccompRetEPERM {
		t.Errorf("clone(CLONE_NEWUSER) on the real filter: got 0x%x, want EPERM", got)
	}
	if got := runFilter(t, prog, auditArch, unix.SYS_CLONE, 0x11); got != seccompRetAllow {
		t.Errorf("clone(SIGCHLD) on the real filter: got 0x%x, want ALLOW", got)
	}
}
