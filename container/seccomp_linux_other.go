//go:build linux && !amd64 && !arm64

package container

import (
	"fmt"
	"os"
)

// ApplySeccomp is a no-op fallback for Linux architectures without a curated
// BPF filter (anything other than amd64/arm64). We deliberately fail OPEN
// here — skip seccomp with a warning — rather than fail closed. The
// alternative (reusing another architecture's AUDIT_ARCH/syscall-number
// table) would silently kill every container on first syscall, which is
// exactly the arm64-on-x86_64-filter bug this split was created to fix.
func ApplySeccomp() error {
	fmt.Fprintf(os.Stderr, "   ⚠️  Seccomp: no filter available for this architecture, skipping\n")
	return nil
}
