## Project Airlock

### Objective
To demystify containerization by building a functional container runtime from scratch in Go. This tool will securely sandbox a Linux process, proving that containers are just isolated processes, not virtual machines.

### Core Architecture & Primitives
* **Language:** Go (using the `os/exec` and `syscall` packages).
* **Isolation (Namespaces):** `CLONE_NEWPID` (Process IDs), `CLONE_NEWUTS` (Hostnames), `CLONE_NEWNS` (Mount points).
* **Filesystem:** Alpine Linux minimal root filesystem (`rootfs`) constrained via `chroot`.
* **Resource Limits:** Linux Control Groups (Cgroups) v2.

### Scope Boundaries
**In-Scope (The MVP):**
* Running a shell (`/bin/sh`) inside an isolated hostname and PID namespace.
* Swapping the root filesystem to a downloaded Alpine Linux directory.
* Mounting `/proc` so system monitoring tools work locally inside the container.
* Basic memory limitation (e.g., max 100MB RAM) using cgroups.

**Out-of-Scope (To prevent scope creep):**
* Complex networking (veth pairs, bridge networks, port forwarding).
* Automated image pulling from Docker Hub (we will use a static local folder).
* Multi-container orchestration (no Docker Compose features).

### Definition of Done
The project is complete when the following command:
`go run main.go run /bin/sh`
Drops the user into a shell where `hostname` returns "airlock-container", `ps` shows only PID 1 and 2, and the filesystem root `/` contains only Alpine Linux files.# airlock
