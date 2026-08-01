//go:build linux

package container

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// Exec runs command inside the running container identified by targetPID —
// airlock's equivalent of `docker exec`. Stdin/stdout/stderr are wired
// straight to the current process's, so this works interactively.
//
// This shells out to nsenter(1), and that's a deliberate choice, not
// laziness — the rest of this project goes out of its way to avoid
// shelling out (see container/network.go's move to netlink), so it's
// worth explaining why this one case is different.
//
// setns(2) for CLONE_NEWNS (joining a mount namespace) has a hard
// kernel-level restriction: the calling process must be single-threaded at
// the moment of the call. A Go binary never is — the runtime spawns
// several OS threads (GC, sysmon, the scheduler) as a normal part of
// starting up, and those threads share filesystem state (CLONE_FS) the
// same way POSIX threads do, which is exactly the condition setns(2)
// checks for and refuses. There's no way around this from pure Go code
// without dropping to a C constructor that runs before the Go runtime
// initializes (which is literally how runc's own nsenter component is
// built — a small cgo file with a `__attribute__((constructor))` function
// that does the setns() calls before Go's runtime has spawned anything).
// Taking on a cgo dependency for one command felt like a worse trade than
// shelling out to a tool that's essentially universal on Linux (util-linux
// is a base package on every mainstream distro) and exists precisely to
// solve this problem correctly in C, where "single-threaded at the right
// moment" is easy instead of structurally impossible.
func Exec(targetPID int, command string, args []string) error {
	nsenterArgs := append([]string{
		"--target", strconv.Itoa(targetPID),
		"--mount", "--uts", "--ipc", "--net", "--pid",
		"--",
		command,
	}, args...)

	cmd := exec.Command("nsenter", nsenterArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nsenter: %w", err)
	}
	return nil
}
