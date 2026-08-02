//go:build linux

package container

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// containerPS1 builds a shell prompt that visually marks this session as
// "inside a container" rather than the host — the same reason `docker run`
// leaves you at a prompt that shows the container's own hostname: it's easy
// to lose track of which shell a command is about to run in, and running
// something destructive in the wrong one is a real, if boring, way to lose
// work.
//
// This ends up in the PS1 environment variable, which both busybox ash
// (Alpine's default interactive shell) and bash read the same handful of
// backslash escapes from (\h hostname, \w cwd, \$ "#" for root else "$") —
// deliberately not using bash's \[...\] non-printing-width markers around
// the color codes, since ash doesn't understand them and would print them
// literally; the cost is bash slightly mis-tracking cursor position on a
// wrapped line, cosmetic only.
//
// This is best-effort, not a guarantee: an image whose interactive shell
// startup (~/.bashrc, a custom /etc/profile) unconditionally overwrites PS1
// will show its own prompt instead, same as any other environment variable
// a shell's own rc files are free to override. hostname is caller-supplied
// (whatever --hostname resolved to, or an image-derived default) — not
// attacker-controlled input from inside the container, so no escaping
// concerns beyond it already being a valid hostname string.
func containerPS1(hostname string) string {
	const (
		reset   = "\033[0m"
		lock    = "\033[1;35m" // bold magenta
		hostCol = "\033[1;36m" // bold cyan
		pathCol = "\033[34m"   // blue
	)
	return fmt.Sprintf("%s🔒 airlock%s %s\\h%s:%s\\w%s\\$ ", lock, reset, hostCol, reset, pathCol, reset)
}

// announceContainerShell sets the terminal tab/window title to distinguish
// this session from the host's — the same idea as containerPS1, aimed at
// whatever's visible before a single line of output has even scrolled by
// (a prompt only appears once the shell starts; this appears immediately).
//
// isTerminal has to be computed by the CALLER, in container.go's Run,
// before it wraps cmd.Stdout in an io.MultiWriter so every container's
// output also reaches `airlock logs` — that wrapping forces os/exec to
// give this process (Child, running after the re-exec) the write end of a
// plain pipe as its own stdout, never the original terminal fd directly,
// so checking os.Stdout here would report "not a terminal" unconditionally
// regardless of whether the session is genuinely interactive.
//
// The gate matters because the escape sequence, unlike PS1, actively
// writes bytes: on a real terminal it's interpreted and never displayed,
// but on a pipe or a log file it isn't interpreted by anything — skipping
// it keeps `airlock run image cmd > out.txt`, or `airlock logs` piped
// through `less`, free of raw control bytes at the top of the captured
// output.
func announceContainerShell(hostname string, isTerminal bool) {
	if !isTerminal {
		return
	}
	fmt.Printf("\033]0;🔒 airlock: %s\007", hostname)
}

// StdoutIsTerminal reports whether fd 1 is an interactive terminal in
// THIS process, via the same ioctl(TCGETS) approach isatty(3) uses: it
// succeeds only when the fd is a terminal device, so its error-ness alone
// is the answer — no output value is otherwise needed.
//
// Exported and meant to be called exactly once, by container.go's Run,
// before it wraps cmd.Stdout in an io.MultiWriter for log capture — see
// announceContainerShell's doc comment for why it can't be recomputed
// later, inside the re-exec'd Child.
func StdoutIsTerminal() bool {
	_, err := unix.IoctlGetTermios(1, unix.TCGETS)
	return err == nil
}
