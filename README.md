## Project Airlock

### Objective
To demystify containerization by building a functional container runtime from scratch in Go. This tool securely sandboxes a Linux process, proving that containers are just isolated processes — not virtual machines.

---

### Core Architecture & Primitives

| Feature | Implementation |
|---|---|
| Language | Go (`os/exec`, `syscall`, `golang.org/x/sys/unix`) |
| PID isolation | `CLONE_NEWPID` namespace |
| Hostname isolation | `CLONE_NEWUTS` namespace |
| Filesystem isolation | `CLONE_NEWNS` + `pivot_root` to Alpine Linux rootfs |
| /proc | Mounted fresh inside each container |
| Volume mounts | Bind-mounts before `pivot_root`; read-only supported |
| Resource limits | Linux cgroups v2 (memory + CPU quota) |
| Syscall filtering | BPF seccomp filter blocking 8 dangerous syscalls |

---

### Usage

```bash
# Build
go build -o airlock .

# Run a command in a container
airlock run /bin/sh

# Run with volume mounts
airlock run -v /host/path:/container/path /bin/sh -c "ls /container/path"

# Read-only volume
airlock run -v /host/data:/data:ro /bin/sh

# Multiple volumes
airlock run -v /data:/data -v /cfg:/config /bin/sh

# Custom resource limits
airlock run --memory 256m --cpu 75 /bin/sh

# Disable seccomp (rarely needed; auto-detected on linuxkit)
airlock run --no-seccomp /bin/sh
```

---

### Development: Docker Desktop

To test on macOS/Windows (Docker Desktop), build the dev image and run via `--privileged`:

```bash
docker build -t airlock-dev .
docker run --rm -it --privileged airlock-dev bash -c \
  'airlock run -v /tmp:/data /bin/sh'
```

**Seccomp note:** On Docker Desktop, `prctl(PR_SET_SECCOMP)` triggers a kernel-level RCU synchronization deadlock in the linuxkit VM (the lightweight Linux VM powering Docker Desktop on Mac/Windows). Airlock auto-detects the linuxkit kernel via `/proc/version` and skips seccomp gracefully with a warning. The BPF filter is installed normally on native Linux (bare metal, EC2, cloud VMs).

---

### Seccomp: Blocked Syscalls

When running on a native Linux kernel, the following syscalls are blocked with `EPERM` inside every container:

| Syscall | Reason |
|---|---|
| `reboot` | Rebooting the host from inside a container |
| `kexec_load` | Loading a new kernel image |
| `swapon` / `swapoff` | Manipulating swap devices |
| `mount` | Remounting host filesystems |
| `pivot_root` | Escaping the container root |
| `settimeofday` | Manipulating the system clock |
| `perf_event_open` | Side-channel attacks via perf |

---

### Scope

**Implemented:**
- PID, UTS, and mount namespace isolation
- `pivot_root` to Alpine Linux rootfs (with chroot fallback)
- `/proc` mount
- Volume mounts (rw and ro)
- Cgroups v2 (memory + CPU)
- BPF seccomp filter (native Linux); auto-skip on linuxkit

**Out of scope (future work):**
- Networking (veth pairs, bridge network, port forwarding)
- Image registry / automatic rootfs pulling
- Multi-container orchestration
