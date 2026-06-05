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
| Filesystem isolation | `CLONE_NEWNS` + `pivot_root` to isolated rootfs |
| Network isolation | `CLONE_NEWNET` + `veth` pair + Linux bridge + `MASQUERADE` NAT |
| /proc | Mounted fresh inside each container |
| Volume mounts | Bind-mounts before `pivot_root`; read-only supported |
| Resource limits | Linux cgroups v2 (memory + CPU quota) |
| Syscall filtering | BPF seccomp filter blocking dangerous syscalls |
| Image Registry | Native OCI/Docker registry pull logic, layer cache, whiteout tar extraction |

---

### Usage: Running Containers

Airlock supports running both the default local Alpine rootfs and pulling native OCI images directly from container registries like Docker Hub or GitHub Container Registry.

```bash
# Build the runtime
go build -o airlock .

# Pull and run an OCI image from Docker Hub
airlock run ubuntu:24.04 /bin/bash -c "echo hello"

# Run a web server and publish a port (Host:Container)
airlock run -p 8080:80 nginx:alpine /docker-entrypoint.sh nginx -g "daemon off;"

# Legacy mode: Run a command using the built-in Alpine mini-rootfs
airlock run /bin/sh

# Mount volumes (Read-Write or Read-Only)
airlock run -v /host/path:/container/path /bin/sh
airlock run -v /host/data:/data:ro /bin/sh

# Custom resource limits
airlock run --memory 256m --cpu 75 alpine:3.20 /bin/sh

# Run completely offline without a network namespace
airlock run --no-network alpine:3.20 /bin/sh
```

---

### Usage: Multi-Container Orchestration

Airlock includes a built-in orchestrator (similar to `docker-compose`) that can parse an `airlock-compose.yml` file, calculate topological dependencies, pre-allocate IPs, and generate internal `/etc/hosts` DNS records so containers can resolve each other by service name.

Create an `airlock-compose.yml` file:
```yaml
version: "1.0"
services:
  database:
    image: redis:alpine
    command: redis-server
    memory: 256m

  web:
    image: nginx:alpine
    command: /docker-entrypoint.sh nginx -g "daemon off;"
    ports:
      - "8080:80"
    depends_on:
      - database
```

Manage the stack:
```bash
# Start all services in dependency order
airlock compose up

# Stop and remove all services in the stack
airlock compose down

# List running containers and their service names
airlock ps
```

---

### Usage: Housekeeping

Images, blobs, container state, and rootfs layers are cached locally to speed up startup times.

```bash
# List all running containers
airlock ls

# Clean up default Alpine rootfs and stale state files
airlock clean

# Clean up pulled OCI image layers and blobs
airlock clean --images

# Nuke the entire ~/.airlock directory
airlock clean --all
```

---

### Development: Docker Desktop

To test on macOS/Windows (Docker Desktop), build the dev image and run via `--privileged`.

```bash
docker build -t airlock-dev .
docker run --rm -it --privileged airlock-dev bash
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

### E2E Testing

Airlock includes a comprehensive 40-step End-to-End (E2E) Bash test suite (`test_e2e.sh`) that validates the entire container lifecycle, isolation, registry pulling, networking, and orchestration.

To run the test suite:
```bash
docker build -t airlock-dev .
docker run --rm --privileged airlock-dev bash /app/test_e2e.sh
```
