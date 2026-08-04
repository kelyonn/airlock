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

// allowedSyscalls is the set of syscalls permitted inside airlock containers
// on x86_64 — everything else the kernel exposes is denied (EPERM) by
// buildFilter's default branch. 272 entries, derived from Docker's
// own default seccomp profile (moby/moby's daemon/pkg/oci/fixtures/default.json,
// the same reference containerd, CRI-O, and most other OCI runtimes converge
// on), not independently hand-picked — this project's own prior seccomp
// incident (a wrong default-deny branch instantly killed every container on
// arm64, see auditArch's history in the arm64 variant of this file) is
// exactly the failure mode a self-curated allow-list risks reproducing at
// far larger scale, so this deliberately isn't one.
//
// This isn't a mechanical transcription, though — Docker's real profile has
// per-syscall conditions (capability requirements, architecture gates,
// specific argument values) that a flat allow-list can't represent, and
// three categories needed resolving by hand rather than copying blindly:
//
//   - Syscalls Docker gates on a specific capability are included here only
//     where airlock's OWN fixed capability bounding set (container/capabilities.go)
//     actually grants that capability — chroot (CAP_SYS_CHROOT) is the only
//     one that qualifies; everything gated on CAP_SYS_ADMIN, CAP_SYS_BOOT,
//     CAP_SYS_TIME, CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_SYS_RAWIO,
//     CAP_SYS_NICE, CAP_SYS_PACCT, CAP_SYS_TTY_CONFIG, CAP_SYSLOG, or
//     CAP_DAC_READ_SEARCH is correctly absent, since airlock grants none of
//     those — this doesn't need re-deriving per container the way Docker's
//     own --cap-add/--cap-drop-aware daemon does, because airlock's
//     capability set never varies between containers.
//   - clone and personality are gated in Docker's profile on specific
//     argument VALUES (e.g. which clone(2) flags are set), which needs
//     actual per-argument BPF comparison instructions (loading the syscall's
//     argument words from seccomp_data, not just its number) — a genuinely
//     separate, larger piece of BPF assembly than the flat number-matching
//     buildFilter already does. Deliberately out of scope here: both are
//     allowed unconditionally instead, a real, stated simplification rather
//     than a silent one. This is also not optional in practice — clone
//     specifically is what fork() and every thread creation ultimately
//     lowers to, so some allowance for it is load-bearing for basically any
//     real program, not a nice-to-have.
//   - mknod and mknodat are DELIBERATELY excluded even though Docker's own
//     profile allows them unconditionally — airlock already made this call
//     before this file existed (see the capability comment in
//     capabilities.go: CAP_MKNOD is kept in the bounding set specifically so
//     images can mknod their own tmpfs-backed /dev at startup, "fenced in by
//     seccomp" as the deliberate second layer). Adopting Docker's list
//     wholesale would have silently undone that — this is the one place this
//     allow-list is intentionally MORE restrictive than the reference it's
//     otherwise built from.
var allowedSyscalls = []uint32{
	unix.SYS_ACCEPT,
	unix.SYS_ACCEPT4,
	unix.SYS_ACCESS,
	unix.SYS_ADJTIMEX,
	unix.SYS_ALARM,
	unix.SYS_ARCH_PRCTL,
	unix.SYS_BIND,
	unix.SYS_BRK,
	unix.SYS_CAPGET,
	unix.SYS_CAPSET,
	unix.SYS_CHDIR,
	unix.SYS_CHMOD,
	unix.SYS_CHOWN,
	unix.SYS_CHROOT,
	unix.SYS_CLOCK_GETRES,
	unix.SYS_CLOCK_GETTIME,
	unix.SYS_CLOCK_NANOSLEEP,
	unix.SYS_CLONE,
	unix.SYS_CLOSE,
	unix.SYS_CONNECT,
	unix.SYS_COPY_FILE_RANGE,
	unix.SYS_CREAT,
	unix.SYS_DUP,
	unix.SYS_DUP2,
	unix.SYS_DUP3,
	unix.SYS_EPOLL_CREATE,
	unix.SYS_EPOLL_CREATE1,
	unix.SYS_EPOLL_CTL,
	unix.SYS_EPOLL_CTL_OLD,
	unix.SYS_EPOLL_PWAIT,
	unix.SYS_EPOLL_WAIT,
	unix.SYS_EPOLL_WAIT_OLD,
	unix.SYS_EVENTFD,
	unix.SYS_EVENTFD2,
	unix.SYS_EXECVE,
	unix.SYS_EXECVEAT,
	unix.SYS_EXIT,
	unix.SYS_EXIT_GROUP,
	unix.SYS_FACCESSAT,
	unix.SYS_FADVISE64,
	unix.SYS_FALLOCATE,
	unix.SYS_FANOTIFY_MARK,
	unix.SYS_FCHDIR,
	unix.SYS_FCHMOD,
	unix.SYS_FCHMODAT,
	unix.SYS_FCHOWN,
	unix.SYS_FCHOWNAT,
	unix.SYS_FCNTL,
	unix.SYS_FDATASYNC,
	unix.SYS_FGETXATTR,
	unix.SYS_FLISTXATTR,
	unix.SYS_FLOCK,
	unix.SYS_FORK,
	unix.SYS_FREMOVEXATTR,
	unix.SYS_FSETXATTR,
	unix.SYS_FSTAT,
	unix.SYS_FSTATFS,
	unix.SYS_FSYNC,
	unix.SYS_FTRUNCATE,
	unix.SYS_FUTEX,
	unix.SYS_FUTIMESAT,
	unix.SYS_GET_ROBUST_LIST,
	unix.SYS_GET_THREAD_AREA,
	unix.SYS_GETCPU,
	unix.SYS_GETCWD,
	unix.SYS_GETDENTS,
	unix.SYS_GETDENTS64,
	unix.SYS_GETEGID,
	unix.SYS_GETEUID,
	unix.SYS_GETGID,
	unix.SYS_GETGROUPS,
	unix.SYS_GETITIMER,
	unix.SYS_GETPEERNAME,
	unix.SYS_GETPGID,
	unix.SYS_GETPGRP,
	unix.SYS_GETPID,
	unix.SYS_GETPPID,
	unix.SYS_GETPRIORITY,
	unix.SYS_GETRANDOM,
	unix.SYS_GETRESGID,
	unix.SYS_GETRESUID,
	unix.SYS_GETRLIMIT,
	unix.SYS_GETRUSAGE,
	unix.SYS_GETSID,
	unix.SYS_GETSOCKNAME,
	unix.SYS_GETSOCKOPT,
	unix.SYS_GETTID,
	unix.SYS_GETTIMEOFDAY,
	unix.SYS_GETUID,
	unix.SYS_GETXATTR,
	unix.SYS_INOTIFY_ADD_WATCH,
	unix.SYS_INOTIFY_INIT,
	unix.SYS_INOTIFY_INIT1,
	unix.SYS_INOTIFY_RM_WATCH,
	unix.SYS_IO_CANCEL,
	unix.SYS_IO_DESTROY,
	unix.SYS_IO_GETEVENTS,
	unix.SYS_IO_PGETEVENTS,
	unix.SYS_IO_SETUP,
	unix.SYS_IO_SUBMIT,
	unix.SYS_IOCTL,
	unix.SYS_IOPRIO_GET,
	unix.SYS_IOPRIO_SET,
	unix.SYS_KILL,
	unix.SYS_LCHOWN,
	unix.SYS_LGETXATTR,
	unix.SYS_LINK,
	unix.SYS_LINKAT,
	unix.SYS_LISTEN,
	unix.SYS_LISTXATTR,
	unix.SYS_LLISTXATTR,
	unix.SYS_LREMOVEXATTR,
	unix.SYS_LSEEK,
	unix.SYS_LSETXATTR,
	unix.SYS_LSTAT,
	unix.SYS_MADVISE,
	unix.SYS_MEMFD_CREATE,
	unix.SYS_MINCORE,
	unix.SYS_MKDIR,
	unix.SYS_MKDIRAT,
	unix.SYS_MLOCK,
	unix.SYS_MLOCK2,
	unix.SYS_MLOCKALL,
	unix.SYS_MMAP,
	unix.SYS_MODIFY_LDT,
	unix.SYS_MPROTECT,
	unix.SYS_MQ_GETSETATTR,
	unix.SYS_MQ_NOTIFY,
	unix.SYS_MQ_OPEN,
	unix.SYS_MQ_TIMEDRECEIVE,
	unix.SYS_MQ_TIMEDSEND,
	unix.SYS_MQ_UNLINK,
	unix.SYS_MREMAP,
	unix.SYS_MSGCTL,
	unix.SYS_MSGGET,
	unix.SYS_MSGRCV,
	unix.SYS_MSGSND,
	unix.SYS_MSYNC,
	unix.SYS_MUNLOCK,
	unix.SYS_MUNLOCKALL,
	unix.SYS_MUNMAP,
	unix.SYS_NANOSLEEP,
	unix.SYS_NEWFSTATAT,
	unix.SYS_OPEN,
	unix.SYS_OPENAT,
	unix.SYS_PAUSE,
	unix.SYS_PERSONALITY,
	unix.SYS_PIPE,
	unix.SYS_PIPE2,
	unix.SYS_POLL,
	unix.SYS_PPOLL,
	unix.SYS_PRCTL,
	unix.SYS_PREAD64,
	unix.SYS_PREADV,
	unix.SYS_PREADV2,
	unix.SYS_PRLIMIT64,
	unix.SYS_PSELECT6,
	unix.SYS_PTRACE,
	unix.SYS_PWRITE64,
	unix.SYS_PWRITEV,
	unix.SYS_PWRITEV2,
	unix.SYS_READ,
	unix.SYS_READAHEAD,
	unix.SYS_READLINK,
	unix.SYS_READLINKAT,
	unix.SYS_READV,
	unix.SYS_RECVFROM,
	unix.SYS_RECVMMSG,
	unix.SYS_RECVMSG,
	unix.SYS_REMAP_FILE_PAGES,
	unix.SYS_REMOVEXATTR,
	unix.SYS_RENAME,
	unix.SYS_RENAMEAT,
	unix.SYS_RENAMEAT2,
	unix.SYS_RESTART_SYSCALL,
	unix.SYS_RMDIR,
	unix.SYS_RT_SIGACTION,
	unix.SYS_RT_SIGPENDING,
	unix.SYS_RT_SIGPROCMASK,
	unix.SYS_RT_SIGQUEUEINFO,
	unix.SYS_RT_SIGRETURN,
	unix.SYS_RT_SIGSUSPEND,
	unix.SYS_RT_SIGTIMEDWAIT,
	unix.SYS_RT_TGSIGQUEUEINFO,
	unix.SYS_SCHED_GET_PRIORITY_MAX,
	unix.SYS_SCHED_GET_PRIORITY_MIN,
	unix.SYS_SCHED_GETAFFINITY,
	unix.SYS_SCHED_GETATTR,
	unix.SYS_SCHED_GETPARAM,
	unix.SYS_SCHED_GETSCHEDULER,
	unix.SYS_SCHED_RR_GET_INTERVAL,
	unix.SYS_SCHED_SETAFFINITY,
	unix.SYS_SCHED_SETATTR,
	unix.SYS_SCHED_SETPARAM,
	unix.SYS_SCHED_SETSCHEDULER,
	unix.SYS_SCHED_YIELD,
	unix.SYS_SECCOMP,
	unix.SYS_SELECT,
	unix.SYS_SEMCTL,
	unix.SYS_SEMGET,
	unix.SYS_SEMOP,
	unix.SYS_SEMTIMEDOP,
	unix.SYS_SENDFILE,
	unix.SYS_SENDMMSG,
	unix.SYS_SENDMSG,
	unix.SYS_SENDTO,
	unix.SYS_SET_ROBUST_LIST,
	unix.SYS_SET_THREAD_AREA,
	unix.SYS_SET_TID_ADDRESS,
	unix.SYS_SETFSGID,
	unix.SYS_SETFSUID,
	unix.SYS_SETGID,
	unix.SYS_SETGROUPS,
	unix.SYS_SETITIMER,
	unix.SYS_SETPGID,
	unix.SYS_SETPRIORITY,
	unix.SYS_SETREGID,
	unix.SYS_SETRESGID,
	unix.SYS_SETRESUID,
	unix.SYS_SETREUID,
	unix.SYS_SETRLIMIT,
	unix.SYS_SETSID,
	unix.SYS_SETSOCKOPT,
	unix.SYS_SETUID,
	unix.SYS_SETXATTR,
	unix.SYS_SHMAT,
	unix.SYS_SHMCTL,
	unix.SYS_SHMDT,
	unix.SYS_SHMGET,
	unix.SYS_SHUTDOWN,
	unix.SYS_SIGALTSTACK,
	unix.SYS_SIGNALFD,
	unix.SYS_SIGNALFD4,
	unix.SYS_SOCKET,
	unix.SYS_SOCKETPAIR,
	unix.SYS_SPLICE,
	unix.SYS_STAT,
	unix.SYS_STATFS,
	unix.SYS_STATX,
	unix.SYS_SYMLINK,
	unix.SYS_SYMLINKAT,
	unix.SYS_SYNC,
	unix.SYS_SYNC_FILE_RANGE,
	unix.SYS_SYNCFS,
	unix.SYS_SYSINFO,
	unix.SYS_TEE,
	unix.SYS_TGKILL,
	unix.SYS_TIME,
	unix.SYS_TIMER_CREATE,
	unix.SYS_TIMER_DELETE,
	unix.SYS_TIMER_GETOVERRUN,
	unix.SYS_TIMER_GETTIME,
	unix.SYS_TIMER_SETTIME,
	unix.SYS_TIMERFD_CREATE,
	unix.SYS_TIMERFD_GETTIME,
	unix.SYS_TIMERFD_SETTIME,
	unix.SYS_TIMES,
	unix.SYS_TKILL,
	unix.SYS_TRUNCATE,
	unix.SYS_UMASK,
	unix.SYS_UNAME,
	unix.SYS_UNLINK,
	unix.SYS_UNLINKAT,
	unix.SYS_UTIME,
	unix.SYS_UTIMENSAT,
	unix.SYS_UTIMES,
	unix.SYS_VFORK,
	unix.SYS_VMSPLICE,
	unix.SYS_WAIT4,
	unix.SYS_WAITID,
	unix.SYS_WRITE,
	unix.SYS_WRITEV,
}

// ApplySeccomp installs a pure-Go BPF seccomp filter that allows only
// allowedSyscalls, denying (EPERM) everything else.
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

	filter := buildFilter(auditArch, allowedSyscalls)
	if err := installFilter(filter); err != nil {
		return err
	}

	if Verbose {
		fmt.Printf("   🔐 Seccomp: allow-list of %d syscalls, deny-by-default otherwise\n", len(allowedSyscalls))
	}
	return nil
}
