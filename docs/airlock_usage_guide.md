# Airlock: Usage & Operations Guide
### Everything You Need to Run Containers

---

## Table of Contents
1. Prerequisites & Environment Setup
2. Building Airlock
3. Running Your First Container
4. Working with OCI Images
5. Port Forwarding
6. Volume Mounts
7. Resource Limits (CPU & Memory)
8. Disabling Features (Debug Mode)
9. Container State: `ps` / `ls` / `clean`
10. Multi-Container Stacks (`compose`)
11. The `airlock-compose.yml` Format Reference
12. Known Limitations
13. Quick Cheatsheet

---

## 1. Prerequisites & Environment Setup

Airlock talks directly to the Linux kernel. It **cannot run natively on macOS or Windows**. You must use Linux.

### On Linux (Recommended)
Ubuntu, Debian, Fedora, or Arch Linux with a kernel ≥ 4.9 (for cgroups v2 support).
```bash
# Install Go 1.21+
sudo apt-get install golang-go

# Build and run
go build -o airlock .
sudo ./airlock run alpine /bin/sh
```

> **Note:** Most operations need `root` because creating namespaces, mounting filesystems, and modifying iptables all require elevated privileges.

### On macOS or Windows (Docker Dev Environment)
We provide a `Dockerfile` that sets up a complete Linux development environment.

**Step 1 — Build the dev image (one-time setup):**
```bash
docker build -t airlock-dev .
```

**Step 2 — Start an interactive privileged shell:**
```bash
docker run -v $(pwd):/app -w /app --rm -it --privileged airlock-dev bash
```

- `-v $(pwd):/app` — mounts your local project directory inside the container so your code changes are immediately visible inside.
- `--privileged` — grants the Docker container full Linux kernel permissions (required for namespaces, cgroups, iptables).
- `-w /app` — sets the working directory to your project.

**Step 3 — Inside the shell, build and run:**
```bash
go build -o airlock .
./airlock run alpine /bin/sh
```

---

## 2. Building Airlock

```bash
# Standard build (produces the 'airlock' binary)
go build -o airlock .

# Cross-compile for Linux from macOS (produces a Linux binary)
GOOS=linux go build -o airlock .

# Run the full test suite (must be inside the privileged Docker environment)
bash test_e2e.sh
```

---

## 3. Running Your First Container

The `run` command pulls an OCI image and executes a command inside a fully isolated container.

```
airlock run [OPTIONS] IMAGE COMMAND [ARGS...]
```

**Examples:**
```bash
# Interactive Alpine shell (most minimal image, boots in ~1 second)
./airlock run alpine /bin/sh

# Interactive Ubuntu bash shell
./airlock run ubuntu:24.04 /bin/bash

# Run a one-shot command and print output
./airlock run alpine /bin/sh -c "echo hello from a container"

# Run as a custom hostname
./airlock run --hostname mybox alpine /bin/sh
```

### Legacy Mode (No Image)
If the first argument starts with `/`, Airlock uses the built-in Alpine mini-rootfs instead of pulling an image. Useful for quick offline testing:
```bash
./airlock run /bin/sh
./airlock run /bin/sh -c "echo hello"
```

### What You'll See on First Run
```
🔒 Airlock: Starting container...
⬇  Pulling registry-1.docker.io/library/alpine:latest...
🔍 Image has 1 layer(s)
   Layer 1/1: sha256:abcd1234...
✓  Image ready: registry-1.docker.io/library/alpine:latest
   Memory limit: 100m
   CPU limit: 50%
🔒 Entering container (hostname: airlock-container)
   Type 'exit' to leave the container.

/ #
```

On the second run, the image is cached and starts almost instantly:
```
✓  Using cached registry-1.docker.io/library/alpine:latest
```

---

## 4. Working with OCI Images

Airlock supports the full OCI image reference format:

| Format | Example | Notes |
|---|---|---|
| `name` | `alpine` | Resolves to `docker.io/library/alpine:latest` |
| `name:tag` | `alpine:3.20` | Specific version |
| `org/name:tag` | `bitnami/redis:7.0` | Docker Hub org |
| `registry/org/name:tag` | `ghcr.io/owner/repo:v1.0` | Custom registry |

Images are cached at `~/.airlock/images/`. Cache is keyed by full registry + name + tag.

---

## 5. Port Forwarding

Expose a port from inside the container to your host machine using the `-p` flag.

```bash
# Forward host port 8080 to container port 80
./airlock run -p 8080:80 python:alpine python3 -m http.server 80
```

After this starts, open another terminal and test:
```bash
curl http://localhost:8080
# or in a browser: http://localhost:8080
```

You can forward multiple ports:
```bash
./airlock run -p 8080:80 -p 9090:9090 myimage /start.sh
```

**How it works:** Airlock installs an `iptables` DNAT rule on the host:
```
PREROUTING: TCP port 8080 → DNAT → 10.0.42.X:80
```
Any connection to `localhost:8080` is transparently redirected by the kernel to the container's IP.

---

## 6. Volume Mounts

Bind-mount a directory from your host into the container with `-v`:

```
-v <host_path>:<container_path>[:<options>]
```

**Read-Write Mount (default):**
```bash
# The container can read AND write to /data
./airlock run -v /tmp/mydata:/data alpine /bin/sh -c "echo hello > /data/file.txt"

# Verify the file was written to the host:
cat /tmp/mydata/file.txt
# hello
```

**Read-Only Mount:**
```bash
# The container cannot write to /config
./airlock run -v /etc/myapp:/config:ro alpine /bin/sh -c "cat /config/settings.json"
```

Airlock validates that host paths exist before starting the container, giving a clear error rather than a cryptic mount failure.

---

## 7. Resource Limits (CPU & Memory)

Airlock enforces hard resource limits using Linux Cgroups v2.

### Memory
```bash
# Limit container to 256MB RAM
./airlock run --memory 256m alpine /bin/sh

# Limit to 1GB
./airlock run --memory 1g ubuntu /bin/bash

# Supported units: k (kilobytes), m (megabytes), g (gigabytes)
```

If the container exceeds the memory limit, the Linux OOM (Out-Of-Memory) killer immediately terminates it.

### CPU
```bash
# Limit container to 50% of one CPU core (default)
./airlock run --cpu 50 alpine /bin/sh

# Limit to 10% (useful for background tasks)
./airlock run --cpu 10 alpine /bin/sh

# Allow up to 100% (still on one core)
./airlock run --cpu 100 alpine /bin/sh
```

CPU limits use the cgroups v2 `cpu.max` interface. `--cpu 50` writes `50000 100000` meaning: *use at most 50,000 microseconds out of every 100,000 microsecond period.*

---

## 8. Disabling Features (Debug Mode)

These flags are primarily for debugging and development.

### `--no-seccomp`
Disables the syscall filter. The container can make any syscall the kernel allows. Use when debugging unexpected `EPERM` errors:
```bash
./airlock run --no-seccomp alpine /bin/sh
```

### `--no-network`
Starts the container with a completely empty network namespace. No interfaces, no internet, no inter-container communication:
```bash
./airlock run --no-network alpine /bin/sh
# Inside: ip addr → only shows 'lo' (if brought up manually)
```

---

## 9. Container State: `ps` / `ls` / `clean`

### View Running Containers
```bash
./airlock ps
# or
./airlock ls
```

Output:
```
ID         PID    IMAGE           COMMAND     IP           SERVICE     COMPOSE FILE
1234567    1234   alpine:latest   /bin/sh     10.0.42.2    -           -
```

### Clean Up

```bash
# Remove state files for containers that have already exited
./airlock clean

# Delete all downloaded image layers (frees disk space)
./airlock clean --images

# Remove everything: state + images
./airlock clean --all
```

State files are stored in `~/.airlock/state/`. Image layers are stored in `~/.airlock/images/`.

---

## 10. Multi-Container Stacks (`compose`)

For applications requiring multiple containers, Airlock includes a built-in orchestrator.

### Starting a Stack
```bash
# Reads airlock-compose.yml from the current directory
./airlock compose up
```

### Stopping a Stack
```bash
./airlock compose down
```

### Viewing Stack Status
```bash
./airlock ls   # Services running from a compose stack show their SERVICE name and COMPOSE FILE
```

---

## 11. The `airlock-compose.yml` Format Reference

```yaml
version: "1.0"

services:
  <service-name>:
    # Required: OCI image reference (same format as 'airlock run')
    image: redis:alpine

    # Required: command to run (must be a single string, space-split)
    # ⚠️ WARNING: Do NOT use quoted arguments with spaces (see Known Limitations)
    command: redis-server --port 6379

    # Memory limit (k/m/g suffixes supported)
    memory: 256m

    # CPU percentage limit (1-100)
    cpu: 50

    # Port forwards (host:container format)
    ports:
      - "8080:80"

    # Volume mounts (host:container[:ro] format)
    volumes:
      - "/data/redis:/data"

    # Environment variables passed into the container
    environment:
      - "REDIS_PASSWORD=secret"

    # Boot order: this service waits for 'db' to start first
    depends_on:
      - db
```

### A Working Example

```yaml
version: "1.0"
services:
  database:
    image: redis:alpine
    command: redis-server
    memory: 256m
    cpu: 25

  web:
    image: python:alpine
    command: python3 -m http.server 80
    memory: 128m
    ports:
      - "8080:80"
    depends_on:
      - database
```

After `./airlock compose up`, you can `curl http://localhost:8080` to reach the Python web server. The web container can reach the Redis database at the hostname `database` (Airlock injects this into `/etc/hosts`).

---

## 12. Known Limitations

### Command Parsing in Compose (fixed)
The compose `command:` field now goes through a small quote-aware tokenizer (`internal/shellwords`) instead of a bare whitespace split, so shell-style quoting works. An explicit YAML list is also accepted if you'd rather sidestep quoting entirely.

```yaml
# Both of these now parse correctly:
command: nginx -g "daemon off;"
command: ["nginx", "-g", "daemon off;"]

command: python3 -m http.server 80
command: redis-server
command: sleep 3600
```

### macOS / Windows: Must Use Docker
Airlock requires a Linux kernel. On macOS or Windows, you must build and run inside the provided Docker development environment (`docker run --privileged airlock-dev bash`).

### Seccomp Skipped on Linuxkit (Docker Desktop)
When running inside Docker Desktop, the underlying Linux VM (Linuxkit) uses a single virtual CPU. The Linux kernel's seccomp filter synchronization deadlocks on single-vCPU machines. Airlock detects this and automatically skips seccomp with a warning:
```
⚠  Seccomp: skipped (not supported in this kernel/environment)
```
This is expected behavior on macOS/Windows development environments.

### No User Namespace Isolation
Airlock currently does not use `CLONE_NEWUSER`. This means the container runs as the same user as the host process (typically root). A future version should support user namespaces for rootless container execution.

---

## 13. Quick Cheatsheet

```bash
# Run a container
./airlock run IMAGE COMMAND [ARGS...]

# Run with port forward
./airlock run -p HOST_PORT:CONTAINER_PORT IMAGE COMMAND

# Run with volume mount
./airlock run -v HOST_PATH:CONTAINER_PATH[:ro] IMAGE COMMAND

# Run with resource limits
./airlock run --memory 256m --cpu 50 IMAGE COMMAND

# Run without networking
./airlock run --no-network IMAGE COMMAND

# Run without seccomp (debug)
./airlock run --no-seccomp IMAGE COMMAND

# View running containers
./airlock ps
./airlock ls

# Start compose stack
./airlock compose up

# Stop compose stack
./airlock compose down

# Clean up exited container state
./airlock clean

# Delete image cache
./airlock clean --images

# Reset everything
./airlock clean --all
```
