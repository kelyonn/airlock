# Airlock: Complete System Reference
### A Senior Engineer's Guide for the Curious Junior

---

## Table of Contents
1. What Is a Container, Actually?
2. The Architecture: Bird's Eye View
3. The Re-Execution Pattern (`main.go` + `container.go`)
4. Namespace Isolation (`container/namespaces.go`)
5. Filesystem Isolation: `pivot_root` vs `chroot`
6. Virtual Networking (`container/network.go`)
7. Resource Limits via Cgroups v2 (`container/cgroups.go`)
8. Syscall Security via Seccomp BPF (`container/seccomp.go`)
9. OCI Image Pulling (`image/`)
10. Multi-Container Orchestration (`compose/`)
11. Real Bugs Found and Fixed (Production Postmortem)

---

## 1. What Is a Container, Actually?

If you ask a non-engineer what a container is, they will probably say something like: *"It's like a lightweight virtual machine."* This is technically wrong, but conceptually close enough. Let's get precise.

**A Virtual Machine (VM)** uses a *hypervisor* to emulate fake hardware. The VM runs an entirely separate operating system kernel on top of that simulated hardware. VMs are completely isolated but very heavy — they can consume gigabytes of RAM just for the guest OS.

**A container** is just a regular Linux process. There is no separate kernel, no hardware emulation. The container process shares the *exact same kernel* as the host machine. The kernel is simply told to lie to the container — lie about what its hostname is, lie about what files it can see, lie about what network it is on, and enforce strict limits on how much CPU and memory it can consume.

These "lies" and restrictions are implemented by three kernel subsystems that Airlock directly controls:

| Kernel Feature | What It Controls |
|---|---|
| **Namespaces** | What the process can *see* (filesystem, network, PIDs, hostname) |
| **Cgroups v2** | What the process can *use* (CPU quota, RAM limit) |
| **Seccomp BPF** | What the process can *do* (which system calls are allowed) |

Airlock is a Go program that orchestrates all three. When you run `airlock run ubuntu /bin/bash`, Airlock talks directly to the Linux kernel without Docker or any other intermediary.

---

## 2. The Architecture: Bird's Eye View

```
┌──────────────────────────────────────────────────────────────┐
│                     airlock binary                          │
│                                                              │
│  cmd/                                                        │
│  ├── root.go      ← Cobra CLI entrypoint                    │
│  ├── run.go       ← parses flags, builds container.Config   │
│  ├── compose.go   ← delegates to compose.Orchestrator       │
│  ├── list.go      ← reads state files from ~/.airlock/      │
│  ├── clean.go     ← removes state, image cache              │
│  └── version.go   ← prints version string                   │
│                                                              │
│  container/                                                  │
│  ├── container.go     ← Run(): forks the child process      │
│  ├── namespaces.go    ← Child(): sets up the namespace      │
│  ├── devices.go       ← minimal tmpfs /dev (no host bind)   │
│  ├── proc.go          ← hardened, masked /proc mount        │
│  ├── capabilities.go  ← drops the capability bounding set   │
│  ├── network.go       ← bridge, veth pair, iptables DNAT    │
│  ├── cgroups.go       ← writes to /sys/fs/cgroup/           │
│  ├── seccomp*.go      ← per-arch BPF filter (amd64/arm64)   │
│  └── volumes*.go      ← bind-mounts host dirs               │
│                                                              │
│  image/                                                      │
│  └── pull.go          ← downloads OCI image layers          │
│                                                              │
│  compose/                                                    │
│  ├── manifest.go      ← parses airlock-compose.yml          │
│  ├── orchestrator.go  ← starts services in topo order       │
│  └── dns.go           ← injects /etc/hosts for service DNS  │
│                                                              │
│  state/                                                      │
│  └── state.go         ← reads/writes ~/.airlock/state/*.json│
└──────────────────────────────────────────────────────────────┘
```

---

## 3. The Re-Execution Pattern (`main.go` + `container.go`)

### The Problem with Go and `clone()`

To create Linux namespaces, we must call the `clone()` system call with special flags before any threads are running. The Go runtime, however, starts multiple threads (for garbage collection, goroutine scheduling, etc.) *before* your `main()` function runs. If you try to call `unshare()` or set namespace flags after Go has already started its threads, the kernel rejects the call or the result is undefined behavior.

### The Solution: Fork + Re-Execute

Airlock uses the same trick as Docker's `runc`: it forks a fresh copy of *itself* into the new namespaces.

**Step 1 — The Parent (`container.Run`):**
```go
// container/container.go
cmd := exec.Command("/proc/self/exe", "child", rootfsDir, hostname, ...)
cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID |
                syscall.CLONE_NEWNS  | syscall.CLONE_NEWNET,
}
cmd.Start() // ← The kernel creates a new process inside fresh namespaces
```

`/proc/self/exe` is a Linux magic symlink that always points to the currently running binary. So Airlock is literally launching a new copy of itself.

**Step 2 — The Child (`main.go` + `container.Child`):**
```go
// main.go
if len(os.Args) > 1 && os.Args[1] == "child" {
    container.Child(os.Args[2:])
    os.Exit(0)
}
```

The first thing `main()` does is check for the secret `"child"` argument. If it sees it, it bypasses the normal Cobra CLI and calls `container.Child()` directly. `Child()` is now running inside completely empty namespaces, so it can safely call `pivot_root`, mount `/proc`, and configure networking with zero threading interference.

**Why this ordering matters:**
The parent must call `cmd.Start()` and *then* immediately set up the network bridge (`CreateVethPair`). The child's `/proc/<pid>/ns/net` namespace path only exists after the child has started. If the parent tries to set up networking before calling `Start()`, the namespace file doesn't exist yet and the call fails.

---

## 4. Namespace Isolation

Four namespaces are used by Airlock. Each is a `CLONE_NEW*` flag passed to `SysProcAttr.Cloneflags`.

### `CLONE_NEWUTS` — Hostname Isolation
UTS stands for Unix Timesharing System. This namespace lets the container have its own hostname and domainname without affecting the host's. Airlock calls `syscall.Sethostname()` inside the child to set the container's hostname to the value you pass via `--hostname`.

### `CLONE_NEWPID` — Process ID Isolation
Inside the container, the first process (your `/bin/bash` or whatever you run) gets PID 1. It cannot see any processes from the host. When you run `ps aux` inside the container, you only see processes that belong to the container itself. This works because `/proc` is remounted fresh inside the container (see Section 5).

### `CLONE_NEWNS` — Mount Namespace Isolation
This is the most important namespace for filesystem isolation. It creates a private copy of the kernel's mount table for the container. Any `mount()` calls the container makes are invisible to the host. Airlock uses this to `pivot_root` into the container's rootfs and then mount a fresh `/proc`.

### `CLONE_NEWNET` — Network Namespace Isolation
The container gets a completely empty network stack. No interfaces, no routes, no IP address. Airlock then manually wires in a virtual ethernet interface (see Section 6).

---

## 5. Filesystem Isolation: `pivot_root` vs `chroot`

### Why Not Just `chroot`?

`chroot` is a 40-year-old UNIX syscall that changes the apparent root directory. It has a well-known security weakness: if you have root inside a `chroot` jail, you can escape it by calling `chroot()` again from within the jail. Any attacker with root inside a `chroot` can escape to the real filesystem.

`pivot_root` is the modern, secure alternative. It *replaces* the kernel-level mount table entry for `/`. After `pivot_root`, there is no `../../` path that can escape back to the host. The old root is completely detached.

### The `pivot_root` Sequence in Airlock (`namespaces.go`)

```
Step 1: Bind-mount the rootfs directory to itself.
        pivot_root requires the new root to be a proper mount point,
        not just a directory. We satisfy this by:
        syscall.Mount(rootfsDir, rootfsDir, "", syscall.MS_BIND, "")
        Note: We deliberately do NOT use MS_REC here to avoid kernel
        lock contention when source == destination with existing submounts.

Step 2: Bind-mount /dev from the host into the new rootfs.
        The container needs device files (/dev/null, /dev/urandom etc.)
        We do this BEFORE pivot_root while the host path is still reachable.

Step 3: Bind-mount any user-specified volumes (--volume flags).
        These must be mounted BEFORE pivot_root for the same reason.

Step 4: Call syscall.PivotRoot(rootfsDir, rootfsDir+"/.pivot_root")
        The kernel atomically replaces "/" with the container's rootfs.
        The old host root is now accessible at "/.pivot_root".

Step 5: chdir("/") — We must move into the new root.

Step 6: Unmount "/.pivot_root" with MNT_DETACH.
        The host filesystem is now completely gone from the container's view.

Step 7: Mount a fresh "proc" filesystem on /proc.
        Because we are in a new PID namespace, this /proc only shows
        processes belonging to the container.
```

**Fallback to `chroot`:** If `pivot_root` fails (e.g., in some deeply nested Docker environments), Airlock falls back to `syscall.Chroot(rootfsDir)`. This is less secure but functional.

---

## 6. Virtual Networking (`container/network.go`)

When the child process starts with `CLONE_NEWNET`, its network stack is completely empty. Airlock manually builds a virtual network between the host and the container.

### The Bridge (The Virtual Switch)

Airlock creates a Linux bridge called `airlock0` on the host. A bridge is a Layer 2 virtual switch — it works like a physical network switch but entirely in software. The bridge is assigned the IP `10.0.42.1/24` and acts as the default gateway for all containers.

```go
runCmd("ip", "link", "add", "airlock0", "type", "bridge")
runCmd("ip", "addr", "add", "10.0.42.1/24", "dev", "airlock0")
runCmd("ip", "link", "set", "airlock0", "up")
```

### IP Forwarding

For containers to reach the internet, the host kernel must forward packets between the `airlock0` bridge and the external network interface. Airlock enables this by writing to a kernel sysctl:

```go
// ⚠️ BUG FIXED: The original code used "sysctl -w" which is GNU syntax.
// The Alpine/busybox sysctl only accepts "key=value" without the -w flag.
runCmd("sysctl", "net.ipv4.ip_forward=1")
```

### NAT (Masquerading)

The container's IPs are in a private range (`10.0.42.0/24`). The internet doesn't know how to route packets *back* to a private IP. Airlock installs an `iptables` rule called MASQUERADE (a form of NAT) that rewrites the source IP of outgoing container packets to look like they came from the host's real IP:

```go
runCmd("iptables", "-t", "nat", "-A", "POSTROUTING",
    "-s", "10.0.42.0/24", "!", "-o", "airlock0",
    "-j", "MASQUERADE")
```

### The Virtual Ethernet Pair (veth)

A `veth` pair is like a two-ended pipe. Packets pushed into one end come out the other. Airlock creates a pair with two interfaces, plugs one end into the `airlock0` bridge, and moves the other end into the container's network namespace using `nsenter`:

```go
// Create the cable
runCmd("ip", "link", "add", "veth-<id>", "type", "veth", "peer", "name", "vethp-<id>")
// Plug host-side into the bridge
runCmd("ip", "link", "set", "veth-<id>", "master", "airlock0")
// Move peer end into the container's namespace
runCmd("ip", "link", "set", "vethp-<id>", "netns", containerPID)
// Inside the namespace: rename to eth0 and assign IP
runCmd("nsenter", "--net=...", "ip", "link", "set", "vethp-<id>", "name", "eth0")
runCmd("nsenter", "--net=...", "ip", "addr", "add", "10.0.42.X/24", "dev", "eth0")
```

### The Race Condition Bug and the Fix

After the parent calls `nsenter` to inject `eth0` into the container, the child process is already running and may try to `ip link set eth0 up` before the parent has finished. This is a classic **race condition**.

The original code simply tried once and printed a warning. The fixed code retries in a loop for up to 100ms:

```go
// ⚠️ BUG FIXED: Added retry loop to handle parent/child race condition.
var eth0Err error
for i := 0; i < 10; i++ {
    if eth0Err = runCmd("ip", "link", "set", "eth0", "up"); eth0Err == nil {
        break
    } else if err2 := runCmd("ifconfig", "eth0", "up"); err2 == nil {
        eth0Err = nil
        break
    }
    time.Sleep(10 * time.Millisecond) // Wait for parent to finish injecting veth
}
```

---

## 7. Resource Limits via Cgroups v2 (`container/cgroups.go`)

Cgroups v2 (Control Groups version 2) is a Linux kernel feature that enforces hard resource limits on process trees. In the cgroup v2 unified hierarchy, everything lives under `/sys/fs/cgroup/`. The kernel continuously monitors the files in that directory and enforces limits.

Setting a limit is as simple as writing a string into a file:

```bash
# Set memory limit to 256MB
echo 268435456 > /sys/fs/cgroup/airlock-1234/memory.max

# Limit CPU to 50% (50,000 out of every 100,000 microseconds)
echo "50000 100000" > /sys/fs/cgroup/airlock-1234/cpu.max

# Assign this process to the cgroup
echo 1234 > /sys/fs/cgroup/airlock-1234/cgroup.procs
```

### The Docker-in-Docker Problem

When Airlock runs *inside* Docker (for development on macOS), it is already inside a leaf cgroup. The Linux kernel does not allow a leaf cgroup to create child cgroups directly. Airlock handles this gracefully:

```go
func tryCreateChildCgroup(pid int) (string, bool) {
    // Try to create a child cgroup
    if err := os.MkdirAll(cgroupPath, 0755); err != nil {
        // Can't create child — write limits directly to current cgroup
        return cgroupRoot, false
    }
    // Check if controllers were actually delegated
    if _, err := os.Stat(filepath.Join(cgroupPath, "memory.max")); err != nil {
        os.Remove(cgroupPath)
        return cgroupRoot, false // Fall back to current cgroup
    }
    return cgroupPath, true
}
```

---

## 8. Syscall Security via Seccomp BPF (`container/seccomp.go`)

Even with namespaces, a container can still make *any* system call to the same Linux kernel as the host. A malicious process inside the container could call `reboot()` to crash the entire server, or `kexec_load()` to replace the running kernel.

Seccomp (Secure Computing Mode) installs a filter that intercepts every system call the process attempts. If the system call is on the blocklist, the kernel immediately returns `EPERM` (Permission Denied) without executing the call.

### Raw BPF Bytecode in Go

Instead of using a library, Airlock writes **raw BPF (Berkeley Packet Filter) instructions** directly in Go. BPF is a tiny virtual machine built into the Linux kernel. The filter program is loaded with `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`.

Before loading the filter, Airlock must call `prctl(PR_SET_NO_NEW_PRIVS, 1)`. This prevents the container from gaining extra privileges via `setuid` binaries, which is a hard kernel requirement before applying seccomp to a non-root process.

### The Linuxkit Deadlock Bug

Running Airlock inside Docker Desktop on macOS means running inside a tiny invisible Linux VM called **Linuxkit**, which is typically configured with only **one virtual CPU core**. When a seccomp filter is applied, the kernel must broadcast the new rules to all CPU cores using an RCU (Read-Copy-Update) synchronization mechanism. On single-vCPU VMs, this synchronization deadlocks — the process hangs forever waiting for other CPUs that don't exist.

Airlock detects this environment and skips seccomp:
```go
func isLinuxkit() bool {
    data, err := os.ReadFile("/proc/version")
    if err != nil { return false }
    return bytes.Contains(bytes.ToLower(data), []byte("linuxkit"))
}
```

---

## 9. OCI Image Pulling (`image/`)

When you type `airlock run ubuntu /bin/bash`, Airlock downloads the image from Docker Hub using the **OCI (Open Container Initiative) Distribution Specification**.

### The Pull Sequence
1. **Auth Token:** Airlock sends a GET to `https://auth.docker.io/token?service=...&scope=pull:ubuntu` to obtain a short-lived JWT token.
2. **Manifest:** Using the token, Airlock fetches the image manifest from `registry-1.docker.io`. The manifest is a JSON document listing all the layer SHA256 hashes.
3. **Config Blob:** The manifest points to a config blob that contains environment variables, the default `CMD`, and the `ENTRYPOINT` defined by the image author.
4. **Layer Tarballs:** Each layer is a `.tar.gz` archive. Airlock downloads and extracts them in order, with later layers overwriting earlier ones.
5. **Caching:** All downloaded layers are cached at `~/.airlock/images/<registry>/<image>/<tag>/`. Subsequent runs skip the download entirely.

### Whiteout Files
The OCI spec handles file *deletions* across layers using **whiteout files**. If Layer 2 needs to delete `secret.txt` that existed in Layer 1, it contains an empty file named `.wh.secret.txt`. Airlock detects these during extraction and deletes the corresponding real files.

---

## 10. Multi-Container Orchestration (`compose/`)

Real applications need multiple containers that depend on each other. Airlock includes a compose orchestrator that reads an `airlock-compose.yml` file.

### Dependency Resolution (Topological Sort)
The `depends_on` relationships form a **Directed Acyclic Graph (DAG)**. Airlock uses a depth-first-search topological sort to find a valid boot order. If there is a cycle (e.g., `A` depends on `B`, `B` depends on `A`), the orchestrator detects it and returns an error before starting anything.

### Service DNS (Host Injection)
Containers don't know each other's IP addresses. Before starting each container, Airlock's DNS injector writes to `/etc/hosts` inside the container's rootfs:
```
10.0.42.5   database
10.0.42.6   cache
```
This allows the web service to connect to `http://database:5432` without any service discovery infrastructure.

### The Command-Parsing Limitation (fixed)
The compose orchestrator originally parsed the `command:` field with Go's `strings.Fields()`, which splits on whitespace with no concept of quoting — `nginx -g "daemon off;"` came out as four broken arguments (`nginx`, `-g`, `"daemon`, `off;"`) instead of three correct ones. That's since been replaced with a small quote-aware tokenizer (`internal/shellwords`), and `command:` also accepts an explicit YAML list (`["nginx", "-g", "daemon off;"]`) for anyone who'd rather not rely on quote-splitting at all:
```yaml
# Both now parse correctly — this used to be the broken example:
command: nginx -g "daemon off;"
command: ["nginx", "-g", "daemon off;"]
```
See `internal/shellwords/shellwords.go` and `compose/manifest.go`'s `StringOrSlice` type.

---

## 11. Real Bugs Found and Fixed (Production Postmortem)

These are real bugs discovered when actually running the project end-to-end. They are documented here so you understand what can go wrong in systems programming.

### Bug #1: `sysctl -w` Not Supported in Alpine
**File:** `container/network.go`
**Symptom:** `warning: bridge setup failed: sysctl [-w net.ipv4.ip_forward=1]: unrecognized option: w`
**Root Cause:** The GNU coreutils version of `sysctl` accepts `-w key=value`. The busybox version (used in Alpine Linux) does not support `-w` and uses `key=value` directly.
**Fix:** Removed the `-w` flag.
```diff
- runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
+ runCmd("sysctl", "net.ipv4.ip_forward=1")
```

### Bug #2: Race Condition on eth0 Interface Setup
**File:** `container/namespaces.go`
**Symptom:** `warning: bring up eth0: ifconfig [eth0 up]: No such device`
**Root Cause:** The child process starts running and immediately tries to bring up `eth0`. But `eth0` is injected by the *parent* process via `nsenter` slightly *after* the child starts. The child was winning the race.
**Fix:** Added a 10-iteration retry loop with 10ms sleep between attempts, for a maximum wait of 100ms.

### Bug #3: Missing `time` Import Causing Compile Error
**File:** `container/namespaces.go`
**Symptom:** `undefined: time` build error on Linux
**Root Cause:** When the retry loop was added, the `"time"` package was not added to the `import` block. On macOS, the file is excluded by the `//go:build linux` tag, so `go build` on macOS silently succeeded. But a Linux build would fail.
**Fix:** Added `"time"` to the import block.

### Bug #4: Variable Scope Error in Retry Loop
**File:** `container/namespaces.go`
**Symptom:** `undefined: err` compile error
**Root Cause:** The `err` variable from `if err := runCmd(...)` was scoped to the `if` block. Referencing it outside the `if` block is a compile error in Go.
**Fix:** Declared `var eth0Err error` outside the loop and assigned to it inside, so it remains in scope for the final warning message.

---

**A later hardening pass** (after this reference was originally written) fixed several more of this kind — a veth-name collision under concurrent container starts, an unlocked IP-allocation race, and the missing digest verification on downloaded layers — and added a minimal `/dev`, a masked `/proc`, and Linux capability dropping. See the README's [Security model & limitations](../README.md#security-model--limitations) and [Debugging notes](../README.md#debugging-notes) sections for the current state; this document is kept as-is as a record of the original build.
