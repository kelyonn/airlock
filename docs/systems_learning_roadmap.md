# Systems Engineering Learning Roadmap
### From "It Just Works" to "I Know Why It Works"

---

## Introduction: Why You Should Care

If you're a web developer, you probably use Docker every day. You know `docker run`, `docker-compose up`, and you've written a `Dockerfile`. But what happens when something goes wrong inside a container and you don't know where to look? What happens when a container silently runs out of memory, or a port forward mysteriously doesn't work?

The answer is always the same: **you need to understand what the kernel is doing underneath.**

This roadmap is designed to take you from a confident web developer to a systems-literate engineer who can read a container runtime's source code, understand every line, and debug it when something breaks.

We will use the **Airlock** container runtime as our running example — a real, working system you can read, modify, and break.

---

## How to Use This Roadmap

Each Phase has three parts:
1. **The Concept** — what you need to understand and *why* it matters.
2. **Reading** — the best resources (free where possible).
3. **Hands-On Exercise** — something you build yourself, without using Docker.

**Do not skip the exercises.** Reading about systems programming without writing code is almost useless. Systems knowledge only sticks when you've actually broken something and fixed it.

---

## Phase 1: The Kernel is Just Software

### The Concept

Your computer runs two kinds of software simultaneously:
- **The Kernel** ("Ring 0"): The OS kernel. It has total control over hardware — the CPU, RAM, hard drives, and network cards. Only the kernel can read and write to physical hardware.
- **User Processes** ("Ring 3"): Every program you run — your browser, Python, Go, bash — runs in User Space. It has *no* direct access to hardware.

When your Python program writes to a file, it can't do that directly. It has to ask the Kernel to do it on its behalf. This request is called a **System Call (Syscall)**. The kernel exposes hundreds of syscalls — they are the API of the operating system.

When you run `fmt.Println("hello")` in Go, Go ultimately calls `write(1, "hello\n", 6)` — the `write` system call, which asks the kernel to write 6 bytes to file descriptor 1 (Standard Output).

Understanding syscalls is the *foundation* of everything else in this roadmap.

### 📚 Reading
- **"The Linux Programming Interface" (TLPI)** by Michael Kerrisk — Read **Chapters 2 and 3** only. These explain the kernel/user space divide and what syscalls are.
- **Julia Evans' strace zine** — Search for "Julia Evans strace". Free and visually excellent.

### 💻 Exercise: Observe Every Syscall Your Program Makes
Write a tiny C or Go program that opens a file and writes to it. Then run it under `strace`:
```bash
strace -e trace=open,write,close ./your_program
```
You will see every single system call your program makes, with its arguments and return values. This is the most powerful debugging tool in Linux.

> **Milestone:** You can explain the difference between `printf()` (a C library function in user space) and `write()` (a kernel syscall). You understand that all I/O goes through the kernel.

---

## Phase 2: Processes and the `fork`/`exec` Model

### The Concept

Where do processes come from? In Linux, every process is created by another process. The very first process (PID 1, `init` or `systemd`) is started by the kernel at boot. Every other process on your system is a descendant of PID 1.

The mechanism is a two-step dance:
1. **`fork()`**: Creates an exact copy of the current process. The copy is called the "child".
2. **`exec()`**: Replaces the child's memory image with a new program.

So when you type `ls` in bash, bash calls `fork()` to create a child copy of itself, then the child calls `exec("/bin/ls")` to replace its memory with the `ls` program. Bash then calls `wait()` to pause until `ls` finishes.

Airlock uses a variation of this: instead of `exec`-ing a different program, it `exec`-s `/proc/self/exe` — a pointer to the *same* Airlock binary — with a secret `"child"` argument. This is the "re-execute" trick that lets it set up Linux namespaces safely.

### 📚 Reading
- **TLPI Chapters 24-26** — Process creation, `fork()`, and `exec()`. Essential.
- **"Computer Systems: A Programmer's Perspective" (CS:APP)** Chapter 8 — "Exceptional Control Flow". Great on process lifecycle.

### 💻 Exercise: Build Your Own Shell (Mini Version)
Write a Go program that:
1. Reads a command from stdin (e.g., `ls -la`)
2. Uses `exec.Command()` to run it
3. Waits for it to finish
4. Loops and asks for the next command

This is a tiny shell. Once it works, add support for running commands in the background with `&` by not calling `Wait()`.

> **Milestone:** You understand what PID 1 is and why it matters. You know the difference between `fork()` and `exec()`. You can explain why zombie processes happen (child exits before parent calls `wait()`).

---

## Phase 3: Namespaces — Teaching the Kernel to Lie

### The Concept

A Linux namespace is a kernel feature that gives a process (and its children) an isolated view of a global resource. Linux has 8 namespace types. Airlock uses 4 of them.

The key insight is: **namespaces don't restrict access to resources — they change what the process *sees*.**

| Namespace | `CLONE_*` Flag | What Changes |
|---|---|---|
| UTS | `CLONE_NEWUTS` | Container has its own hostname |
| PID | `CLONE_NEWPID` | Container's first process is PID 1 |
| Mount | `CLONE_NEWNS` | Container has its own filesystem mount table |
| Network | `CLONE_NEWNET` | Container has its own network stack (empty by default) |

These flags are passed to the `clone()` system call (or `unshare()` for the current process) when the container is created.

### 📚 Reading
- **Liz Rice's "Containers from Scratch" talk** (GopherCon 2018) — Find it on YouTube. She writes a container runtime in ~100 lines of Go, live on stage. This is the single best explanation of container namespaces that exists.
- **Linux `man 7 namespaces`** — The authoritative reference. Read it after Liz's talk.

### 💻 Exercise: Create a Namespace Without Any Code
You can create a new namespace entirely from the command line using `unshare`:
```bash
# Create a new PID namespace and run bash inside it
sudo unshare --pid --fork --mount-proc /bin/bash

# Now inside the new namespace:
ps aux
# You'll only see bash and ps! PID 1 is bash.
echo $$
# Prints "1"

exit  # Back to the real world
```

Try the same with `--uts` (hostname) and `--net` (network).

> **Milestone:** You can use `unshare` and `nsenter` from the command line to create and enter namespaces. You can explain what `CLONE_NEWPID` does to the process's view of `/proc`.

---

## Phase 4: Filesystem Jails — `chroot` and `pivot_root`

### The Concept

Even after creating a Mount Namespace, the container can still see the host's entire filesystem. You need to change the container's root directory (`/`) to point at the container image's directory.

**`chroot` (old, insecure):** Simply changes `path_to_root` for the process. A root-privileged process can escape by calling `chroot` again from inside the jail.

**`pivot_root` (modern, secure):** Atomically replaces the kernel's mount table entry for `/`. There is no `../../` escape because the old root is completely detached at the kernel level.

The full sequence in Airlock is: bind-mount rootfs to itself → mount `/dev` → mount user volumes → `pivot_root` → `chdir("/")` → unmount old root → mount fresh `/proc`.

Order matters enormously here. Every step has to happen in the right sequence or the container fails to isolate correctly.

### 📚 Reading
- **Linux `man 2 pivot_root`** — Read it, even if you don't understand it fully at first.
- **"How Docker implemented the `pivot_root` change"** — Search for this. It's an old Docker issue thread with great discussion.
- **TLPI Chapter 15** — File attributes and the VFS layer.

### 💻 Exercise: Build a Filesystem Jail from Scratch
Without writing any code:
1. Create a directory: `mkdir -p /tmp/myjail/bin /tmp/myjail/lib /tmp/myjail/lib64`
2. Copy bash: `cp /bin/bash /tmp/myjail/bin/`
3. Find bash's dependencies: `ldd /bin/bash`. Copy every `.so` file it needs into `/tmp/myjail/lib/`.
4. Enter the jail: `sudo chroot /tmp/myjail /bin/bash`

You now have a shell that can only see what's inside `/tmp/myjail`. Try running `ls /etc`. It won't find it! But note: you can still escape with another `chroot` call if you have root. This is why `pivot_root` exists.

> **Milestone:** You can build a manual rootfs from scratch. You understand shared library dependencies. You know why `chroot` is insecure and what `pivot_root` adds.

---

## Phase 5: Virtual Networking

### The Concept

When a network namespace is created, the container has zero network interfaces. Airlock must manually build a network:

1. **Bridge** (`airlock0`): A virtual L2 switch. All containers connect to this switch.
2. **`veth` pair**: Two virtual network interfaces wired together like a cable. One end goes in the host namespace, one end goes in the container namespace.
3. **NAT (Masquerade)**: The host rewrites outgoing packets from container IPs to look like they came from the host's real IP. This lets containers reach the internet.
4. **DNAT (Port Forward)**: Incoming traffic on a host port is redirected to a container IP + port.

All of this is configured using the `ip` command (from the `iproute2` package) and `iptables`.

### 📚 Reading
- **"Linux Network Namespaces" tutorial** on `man7.org` — Free and authoritative.
- **`ip` command man page** — `man ip`. Focus on `ip link`, `ip addr`, `ip route`, `ip netns`.
- **`iptables` tutorial** — Search "iptables tutorial tldp". Focus on the `nat` table and `MASQUERADE`/`DNAT` targets.

### 💻 Exercise: Wire Two Namespaces Together by Hand
No code — just shell commands:
```bash
# Create two network namespaces
sudo ip netns add room-a
sudo ip netns add room-b

# Create a veth pair (a virtual ethernet cable)
sudo ip link add veth-a type veth peer name veth-b

# Assign one end to each namespace
sudo ip link set veth-a netns room-a
sudo ip link set veth-b netns room-b

# Assign IPs and bring the interfaces up
sudo ip netns exec room-a ip addr add 10.9.0.1/24 dev veth-a
sudo ip netns exec room-a ip link set veth-a up
sudo ip netns exec room-b ip addr add 10.9.0.2/24 dev veth-b
sudo ip netns exec room-b ip link set veth-b up

# Test connectivity!
sudo ip netns exec room-a ping 10.9.0.2

# Clean up
sudo ip netns del room-a
sudo ip netns del room-b
```

> **Milestone:** You can manually set up two network namespaces and have them communicate. You can explain what NAT is and why containers need it to reach the internet.

---

## Phase 6: Resource Limits — Cgroups v2

### The Concept

Linux cgroups (Control Groups) are a kernel feature that limits, accounts for, and isolates resource usage (CPU, memory, disk I/O) of a collection of processes.

In cgroups **v2** (the modern version), everything is under a single unified hierarchy at `/sys/fs/cgroup/`. Managing resources is as simple as writing text to files in this virtual filesystem.

```bash
# Create a cgroup
mkdir /sys/fs/cgroup/my-limit

# Limit memory to 100MB
echo 104857600 > /sys/fs/cgroup/my-limit/memory.max

# Limit CPU to 25% (25,000 out of 100,000 microseconds)
echo "25000 100000" > /sys/fs/cgroup/my-limit/cpu.max

# Assign a process (by PID) to this cgroup
echo 12345 > /sys/fs/cgroup/my-limit/cgroup.procs
```

The kernel enforces these limits immediately and continuously.

### 📚 Reading
- **Kernel documentation on cgroups v2**: Search "kernel.org cgroup v2 documentation". It is dense but authoritative.
- **"A Linux sysadmin's introduction to cgroups"** on Red Hat developer blog. Excellent practical overview.

### 💻 Exercise: Throttle a Runaway Process
1. Write an infinite loop in Python:
   ```python
   # busyloop.py
   while True: pass
   ```
2. Run it: `python3 busyloop.py &` and note its PID.
3. Check `top` — it's eating 100% CPU.
4. Now throttle it to 5%:
   ```bash
   sudo mkdir /sys/fs/cgroup/throttle
   echo "5000 100000" | sudo tee /sys/fs/cgroup/throttle/cpu.max
   echo <PID> | sudo tee /sys/fs/cgroup/throttle/cgroup.procs
   ```
5. Watch `top` again. The process is instantly throttled to 5%.

> **Milestone:** You can apply cgroup limits from the command line. You understand the quota/period model for CPU limits. You know what the OOM killer is and when it fires.

---

## Phase 7: Syscall Security — Seccomp BPF

### The Concept

Even with namespaces and cgroups, a malicious process inside a container can still make system calls directly to the kernel. Calls like `reboot()`, `kexec_load()`, or `ptrace()` can cause havoc.

**Seccomp** (Secure Computing Mode) installs a filter that runs before every syscall. If the syscall matches the blocklist, the kernel returns `EPERM` before executing it.

Seccomp filters are written in **BPF (Berkeley Packet Filter)** — a tiny, sandboxed virtual machine that runs inside the kernel. The filter is an array of BPF instructions loaded with `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`.

Airlock writes the BPF bytecode directly in Go, without using any C library. This is extremely low-level work.

### 📚 Reading
- **`man 2 seccomp`** — The Linux man page. Read it.
- **"Seccomp Security Profiles for Docker"** — Docker's documentation. Explains the practical use case.
- **BPF overview** — Search "BPF and XDP reference guide Cilium". Comprehensive.

### 💻 Exercise: Trap a Syscall with `strace`
You can "observe" syscalls without a seccomp filter first. Run any program under `strace -c` to get a summary of every syscall it made and how many times:
```bash
strace -c ls /
```
Now write a simple C program that calls `reboot()` (without actually rebooting — you can call it with `LINUX_REBOOT_CMD_HALT` and it will fail with EPERM since you don't have root). See what `strace` shows.

> **Milestone:** You know what seccomp is and why it's needed. You can use `strace` to identify what syscalls any program makes. You understand why `PR_SET_NO_NEW_PRIVS` must be set before loading a seccomp filter.

---

## Phase 8: Multi-Container Systems — DAGs and Topological Sort

### The Concept

Real applications are not one container. They are graphs of containers with dependencies:
- **Web** depends on **Database** and **Cache**
- **Cache** depends on **Database**
- **Database** has no dependencies

This is a **Directed Acyclic Graph (DAG)**. "Directed" because dependencies have direction (A depends on B, not the other way). "Acyclic" because there must be no circular dependencies (if A depends on B and B depends on A, neither can ever start — a deadlock).

To find a valid boot order, we use an algorithm called **Topological Sort**. The result is a linear ordering of services where every service appears after all of its dependencies.

The standard implementation uses Depth-First Search (DFS):
```
1. For each unvisited node, call visit(node)
2. visit(node):
   a. Mark node as "currently visiting" (to detect cycles)
   b. Recursively visit each dependency
   c. Mark node as "visited"
   d. Append node to the result list
3. The result list is in reverse topological order
```

### 📚 Reading
- **"Introduction to Algorithms" (CLRS)** Chapter 22 — Graphs and Topological Sort. The definitive reference.
- **Airlock source**: `compose/manifest.go` and `compose/orchestrator.go` — Read the actual `TopoSort` and `validateDAG` functions.

### 💻 Exercise: Implement Topological Sort
Write a Go (or Python) function that takes this dependency map:
```json
{
  "web":      ["database", "cache"],
  "database": [],
  "cache":    ["database"],
  "worker":   ["database", "cache"]
}
```
And outputs a valid boot order like: `["database", "cache", "web", "worker"]`.

Test it: add a cycle (e.g., `"database": ["web"]`) and make sure your function detects it and returns an error.

> **Milestone:** You can implement topological sort from scratch. You can explain what a DAG is and why container orchestrators use one. You know why circular dependencies cause deadlocks.

---

## What Comes Next

You've now walked through the full stack from user space down to the kernel and back up. You understand how Airlock works end-to-end.

Here are natural next steps for continued growth:

### Explore the OCI Ecosystem
- Read the **OCI Image Specification** and **OCI Runtime Specification** (opencontainers.org). These are the standards that Docker, Kubernetes, and Airlock all implement.
- Read **`runc`'s source code** on GitHub — it is the reference implementation and far more sophisticated than Airlock.

### Learn the Kubernetes Layer
Kubernetes sits *above* container runtimes. It schedules containers across a cluster of machines. Understanding how `kubelet` talks to `containerd` (which talks to `runc`) is the next frontier.

### Dive into eBPF
eBPF is the next generation of BPF. Instead of just filtering syscalls, eBPF programs can run inside the kernel in response to any event — network packets, filesystem operations, system calls, CPU scheduling. It is the foundation of modern observability tools like `bpftrace`, Cilium, and Falco.

### Build Something Real
The best way to cement this knowledge is to build: extend Airlock with a new feature (user namespaces, OCI image build support, a proper shell-quoting parser for the compose command field). Read the bug report. Fix it. Send a PR.
