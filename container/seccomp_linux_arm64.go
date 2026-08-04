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

// allowedSyscalls is the arm64 counterpart to the amd64 file's list of the
// same name — see its doc comment for where this comes from (Docker's own
// default seccomp profile) and the three deliberate deviations from it
// (capability-gated syscalls resolved against airlock's own fixed
// capability set; clone/personality absent here because buildFilter matches
// them with real per-argument BPF blocks instead; mknod/mknodat kept
// excluded on purpose). 230 entries here versus the amd64 file's larger count —
// smaller not because arm64 containers need less, but because arm64's
// syscall ABI is deliberately narrower than x86_64's: it never carried
// forward amd64's 32-bit-compat syscall numbers, and it dropped most of the
// older, non-"at"-suffixed path syscalls (open, mkdir, unlink, stat, and
// similar) in favor of exclusively using their newer openat/mkdirat/unlinkat
// family equivalents, which this list already includes separately —
// confirmed against golang.org/x/sys/unix, which simply has no SYS_ constant
// for any syscall arm64's kernel ABI doesn't define at all.
var allowedSyscalls = []uint32{
	unix.SYS_ACCEPT,
	unix.SYS_ACCEPT4,
	unix.SYS_ADJTIMEX,
	unix.SYS_BIND,
	unix.SYS_BRK,
	unix.SYS_CAPGET,
	unix.SYS_CAPSET,
	unix.SYS_CHDIR,
	unix.SYS_CHROOT,
	unix.SYS_CLOCK_GETRES,
	unix.SYS_CLOCK_GETTIME,
	unix.SYS_CLOCK_NANOSLEEP,
	unix.SYS_CLOSE,
	unix.SYS_CONNECT,
	unix.SYS_COPY_FILE_RANGE,
	unix.SYS_DUP,
	unix.SYS_DUP3,
	unix.SYS_EPOLL_CREATE1,
	unix.SYS_EPOLL_CTL,
	unix.SYS_EPOLL_PWAIT,
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
	unix.SYS_FREMOVEXATTR,
	unix.SYS_FSETXATTR,
	unix.SYS_FSTAT,
	unix.SYS_FSTATFS,
	unix.SYS_FSYNC,
	unix.SYS_FTRUNCATE,
	unix.SYS_FUTEX,
	unix.SYS_GET_ROBUST_LIST,
	unix.SYS_GETCPU,
	unix.SYS_GETCWD,
	unix.SYS_GETDENTS64,
	unix.SYS_GETEGID,
	unix.SYS_GETEUID,
	unix.SYS_GETGID,
	unix.SYS_GETGROUPS,
	unix.SYS_GETITIMER,
	unix.SYS_GETPEERNAME,
	unix.SYS_GETPGID,
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
	unix.SYS_LGETXATTR,
	unix.SYS_LINKAT,
	unix.SYS_LISTEN,
	unix.SYS_LISTXATTR,
	unix.SYS_LLISTXATTR,
	unix.SYS_LREMOVEXATTR,
	unix.SYS_LSEEK,
	unix.SYS_LSETXATTR,
	unix.SYS_MADVISE,
	unix.SYS_MEMFD_CREATE,
	unix.SYS_MINCORE,
	unix.SYS_MKDIRAT,
	unix.SYS_MLOCK,
	unix.SYS_MLOCK2,
	unix.SYS_MLOCKALL,
	unix.SYS_MMAP,
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
	unix.SYS_OPENAT,
	unix.SYS_PIPE2,
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
	unix.SYS_READLINKAT,
	unix.SYS_READV,
	unix.SYS_RECVFROM,
	unix.SYS_RECVMMSG,
	unix.SYS_RECVMSG,
	unix.SYS_REMAP_FILE_PAGES,
	unix.SYS_REMOVEXATTR,
	unix.SYS_RENAMEAT,
	unix.SYS_RENAMEAT2,
	unix.SYS_RESTART_SYSCALL,
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
	unix.SYS_SEMCTL,
	unix.SYS_SEMGET,
	unix.SYS_SEMOP,
	unix.SYS_SEMTIMEDOP,
	unix.SYS_SENDFILE,
	unix.SYS_SENDMMSG,
	unix.SYS_SENDMSG,
	unix.SYS_SENDTO,
	unix.SYS_SET_ROBUST_LIST,
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
	unix.SYS_SIGNALFD4,
	unix.SYS_SOCKET,
	unix.SYS_SOCKETPAIR,
	unix.SYS_SPLICE,
	unix.SYS_STATFS,
	unix.SYS_STATX,
	unix.SYS_SYMLINKAT,
	unix.SYS_SYNC,
	unix.SYS_SYNC_FILE_RANGE,
	unix.SYS_SYNCFS,
	unix.SYS_SYSINFO,
	unix.SYS_TEE,
	unix.SYS_TGKILL,
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
	unix.SYS_UNLINKAT,
	unix.SYS_UTIMENSAT,
	unix.SYS_VMSPLICE,
	unix.SYS_WAIT4,
	unix.SYS_WAITID,
	unix.SYS_WRITE,
	unix.SYS_WRITEV,
}

// ApplySeccomp installs a pure-Go BPF seccomp filter that allows only
// allowedSyscalls, denying (EPERM) everything else. See the amd64 variant's
// doc comment for the linuxkit VM detection rationale.
func ApplySeccomp() error {
	if isLinuxtKitVM() {
		fmt.Fprintf(os.Stderr, "%s\n", seccompUnavailableMsg)
		return nil
	}

	filter := buildFilter(auditArch, allowedSyscalls, argFilteredSyscalls{
		clone:       unix.SYS_CLONE,
		personality: unix.SYS_PERSONALITY,
	})
	if err := installFilter(filter); err != nil {
		return err
	}

	if Verbose {
		fmt.Printf("   🔐 Seccomp: allow-list of %d syscalls, deny-by-default otherwise\n", len(allowedSyscalls))
	}
	return nil
}
