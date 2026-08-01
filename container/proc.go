//go:build linux

package container

import (
	"fmt"
	"os"
	"syscall"
)

// maskedProcFiles are regular files under /proc that leak host information
// or offer a side-channel even with PID namespacing (perf/timing data,
// kernel memory, a lever to crash the host via sysrq). Each is masked by
// bind-mounting /dev/null over it, the same technique runc uses.
var maskedProcFiles = []string{
	"/proc/kcore",
	"/proc/keys",
	"/proc/sysrq-trigger",
	"/proc/timer_list",
	"/proc/sched_debug",
	"/proc/latency_stats",
}

// mountProc mounts the proc filesystem inside the container with the same
// hardening flags runc applies (no setuid binaries, no device nodes, no
// executables backed by /proc), then masks a curated set of sensitive files
// and makes /proc/sys read-only. Must run after setupContainerDev, since
// masking bind-mounts /dev/null (which setupContainerDev creates) over the
// sensitive paths.
func mountProc() error {
	if err := os.MkdirAll("/proc", 0755); err != nil {
		return err
	}
	if err := syscall.Mount("proc", "/proc", "proc",
		syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return err
	}

	for _, path := range maskedProcFiles {
		if _, err := os.Stat(path); err != nil {
			continue // not present on this kernel — nothing to mask
		}
		if err := syscall.Mount("/dev/null", path, "", syscall.MS_BIND, ""); err != nil {
			fmt.Fprintf(os.Stderr, "warning: mask %s failed: %v\n", path, err)
		}
	}

	// /proc/sys is writable by default (sysctl knobs); the mount flags above
	// apply to the whole /proc tree, not to a subtree. Make /proc/sys
	// specifically read-only via the bind-then-remount trick: a plain
	// `mount -o remount,ro /proc/sys` would affect the single shared proc
	// mount, but binding it to itself first gives us an independent mount
	// point we can remount without touching the rest of /proc.
	if err := syscall.Mount("/proc/sys", "/proc/sys", "", syscall.MS_BIND, ""); err == nil {
		roFlags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY |
			syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
		if err := syscall.Mount("", "/proc/sys", "", roFlags, ""); err != nil {
			fmt.Fprintf(os.Stderr, "warning: remount /proc/sys read-only failed: %v\n", err)
		}
	}

	return nil
}
