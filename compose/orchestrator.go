package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kelyonn/airlock/container"
	"github.com/kelyonn/airlock/image"
	"github.com/kelyonn/airlock/state"
)

// serviceStartTimeout bounds how long Up waits for a launched service to
// register itself in the container state file before treating the start
// as failed.
const serviceStartTimeout = 20 * time.Second

// Orchestrator manages the lifecycle of a compose application.
type Orchestrator struct {
	ManifestPath string
	Manifest     Manifest
}

// NewOrchestrator creates a new orchestrator for the given manifest file.
func NewOrchestrator(manifestPath string) (*Orchestrator, error) {
	absPath, err := filepath.Abs(manifestPath)
	if err != nil {
		return nil, err
	}

	manifest, err := ParseManifest(absPath)
	if err != nil {
		return nil, err
	}

	return &Orchestrator{
		ManifestPath: absPath,
		Manifest:     manifest,
	}, nil
}

// Up starts all services in the manifest in dependency order. It returns
// an error — and stops starting further services — the moment any single
// service fails to come up, rather than silently continuing. (The previous
// implementation declared a startErr variable for exactly this purpose but
// never assigned it, so a failed service was only ever reported as a log
// line from inside a background goroutine; Up always returned nil.)
func (o *Orchestrator) Up(verbose bool) error {
	fmt.Printf("🚀 Starting compose stack: %s\n", filepath.Base(o.ManifestPath))

	// Pre-flight: setup the bridge network once for all containers
	if err := container.SetupBridge(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: bridge setup failed: %v\n", err)
	}

	order := TopoSort(o.Manifest.Services)
	serviceIPs := make(map[string]string)

	// Pre-allocate IPs for all services so we can generate /etc/hosts for everyone
	for _, name := range order {
		ip, err := container.AllocateIP()
		if err != nil {
			return fmt.Errorf("allocate IP for %s: %w", name, err)
		}
		serviceIPs[name] = ip
	}

	for _, name := range order {
		svc := o.Manifest.Services[name]
		ip := serviceIPs[name]
		fmt.Printf("\n--- Starting service: %s (%s) ---\n", name, ip)

		if err := o.startService(name, svc, ip, serviceIPs, verbose); err != nil {
			return fmt.Errorf("start service %s: %w", name, err)
		}
	}

	fmt.Println("\n✅ All services started successfully.")
	return nil
}

// startService builds the container config for a single service and hands
// it to launchDetached.
func (o *Orchestrator) startService(name string, svc ServiceDef, myIP string, allIPs map[string]string, verbose bool) error {
	var pfs []container.PortForward
	for _, spec := range svc.Ports {
		parts := strings.SplitN(spec, ":", 2)
		if len(parts) == 2 {
			pfs = append(pfs, container.PortForward{HostPort: parts[0], ContainerPort: parts[1]})
		}
	}

	var mounts []container.VolumeMount
	for _, spec := range svc.Volumes {
		mount, err := container.ParseVolumeSpec(spec)
		if err == nil {
			mounts = append(mounts, mount)
		} else {
			fmt.Fprintf(os.Stderr, "warning: invalid volume spec %q: %v\n", spec, err)
		}
	}

	mem := svc.Memory
	if mem == "" {
		mem = "100m"
	}
	cpu := svc.CPU
	if cpu == 0 {
		cpu = 50
	}

	// Pull the image up front (outside the detached process) so InjectHostsFile
	// can write into the rootfs before the container starts, and so an
	// image-pull failure surfaces here rather than only in a log file.
	// image.ImageConfig is discarded here — the detached process re-derives
	// it itself via container.Run's own image.Pull call (an instant cache
	// hit at that point), the same way it fills in ENTRYPOINT/CMD defaults
	// for a plain `airlock run` when svc.Command is left unset below.
	rootfsDir, _, err := image.Pull(svc.Image, verbose)
	if err != nil {
		return fmt.Errorf("pull image %s: %w", svc.Image, err)
	}

	if err := InjectHostsFile(rootfsDir, allIPs, name, myIP); err != nil {
		fmt.Fprintf(os.Stderr, "warning: inject hosts file failed: %v\n", err)
	}

	// An empty command isn't an error here: leaving Config.Command blank
	// tells container.Run to fall back to the image's own ENTRYPOINT/CMD,
	// exactly like a bare `airlock run redis:alpine` with no trailing
	// command — so `command:` is now optional in a compose manifest for any
	// service whose image already knows how to start itself.
	var command string
	var cmdArgs []string
	if len(svc.Command) > 0 {
		command = svc.Command[0]
		cmdArgs = svc.Command[1:]
	}

	config := container.Config{
		Image:        svc.Image,
		Command:      command,
		Args:         cmdArgs,
		Hostname:     name,
		MemoryLimit:  mem,
		CPULimit:     cpu,
		Verbose:      verbose,
		Volumes:      mounts,
		PortForwards: pfs,
		Env:          svc.Environment,
		ServiceName:  name,
		ComposeFile:  o.ManifestPath,
		ContainerIP:  myIP,
		WorkingDir:   svc.WorkingDir,
		User:         svc.User,
	}

	return o.launchDetached(name, config)
}

// launchDetached starts a service as an independent, detached OS process —
// "airlock __compose-service <config-file>" — rather than a goroutine
// inside the orchestrator's own process.
//
// The previous implementation ran `go container.Run(config)`: a goroutine
// whose lifetime was tied to the orchestrator process. Since Up() returns
// as soon as every service is started, main() would exit right after,
// killing every goroutine and orphaning every container's re-exec'd "child"
// process to init — the stack only kept running by accident, because the
// namespaced child processes happened to survive their parent's death. A
// real subprocess with Setsid has none of that fragility: it has its own
// session, survives the orchestrator exiting on purpose (the -d / detach
// case) or on SIGINT (see cmd/compose.go's foreground handler calling
// Down()), and its exit status is something we can actually check instead
// of guessing with a fixed sleep.
func (o *Orchestrator) launchDetached(name string, config container.Config) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve airlock binary: %w", err)
	}

	cfgJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal service config: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "airlock-compose-*.json")
	if err != nil {
		return fmt.Errorf("write service config: %w", err)
	}
	if _, err := tmpFile.Write(cfgJSON); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return fmt.Errorf("write service config: %w", err)
	}
	tmpFile.Close()

	logPath, logErr := serviceLogPath(o.ManifestPath, name)
	var logFile *os.File
	if logErr == nil {
		logFile, _ = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	}

	cmd := exec.Command(exePath, "__compose-service", tmpFile.Name())
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	// Setsid detaches the service process into its own session, so it
	// survives the orchestrator process exiting (whether that's a deliberate
	// `compose up -d` return or the foreground handler tearing itself down).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		os.Remove(tmpFile.Name())
		if logFile != nil {
			logFile.Close()
		}
		return fmt.Errorf("start service process: %w", err)
	}
	if logFile != nil {
		logFile.Close() // safe once the child has its own inherited fd
	}

	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	deadline := time.After(serviceStartTimeout)
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case werr := <-exitCh:
			return fmt.Errorf("service process exited before it finished starting (log: %s): %w",
				logPathOrUnavailable(logPath, logErr), werr)
		case <-deadline:
			return fmt.Errorf("service %s did not register within %s (log: %s)",
				name, serviceStartTimeout, logPathOrUnavailable(logPath, logErr))
		case <-ticker.C:
			containers, lerr := state.ListByCompose(o.ManifestPath)
			if lerr != nil {
				continue
			}
			for _, c := range containers {
				if c.ServiceName == name {
					fmt.Printf("   ✓ %s started (pid %d, %s)\n", name, c.PID, c.IPAddress)
					return nil
				}
			}
		}
	}
}

func logPathOrUnavailable(path string, err error) string {
	if err != nil {
		return "unavailable"
	}
	return path
}

// serviceLogPath returns (creating parent directories as needed) the log
// file a detached service's stdout/stderr is redirected to. Stacks are
// keyed by a short hash of their manifest's absolute path so two different
// compose files with a same-named service don't collide.
func serviceLogPath(manifestPath, service string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(manifestPath))
	stackDir := filepath.Join(home, ".airlock", "logs", hex.EncodeToString(sum[:])[:12])
	if err := os.MkdirAll(stackDir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(stackDir, service+".log"), nil
}

// Down stops and removes all containers belonging to this compose file.
func (o *Orchestrator) Down() error {
	fmt.Printf("🛑 Stopping compose stack: %s\n", filepath.Base(o.ManifestPath))

	containers, err := state.ListByCompose(o.ManifestPath)
	if err != nil {
		return fmt.Errorf("list compose containers: %w", err)
	}

	if len(containers) == 0 {
		fmt.Println("No running services found for this stack.")
		return nil
	}

	for _, c := range containers {
		fmt.Printf("   Stopping %s (PID %d)...\n", c.ServiceName, c.PID)

		process, ferr := os.FindProcess(c.PID)
		if ferr == nil {
			_ = process.Signal(syscall.SIGTERM)
			if !waitForExit(c.PID, 5*time.Second) {
				_ = process.Signal(syscall.SIGKILL)
				waitForExit(c.PID, 2*time.Second)
			}
		}

		// The container's own process (running container.Run) performs this
		// same cleanup on its way out once the signal above lands. Doing it
		// again here is deliberate defensive belt-and-braces in case that
		// process was already gone (e.g. a prior crash left a stale state
		// entry) — both CleanupNetwork and Unregister are safe to call on an
		// ID that's already been cleaned up.
		container.CleanupNetwork(c.ID)
		state.Unregister(c.ID)
	}

	fmt.Println("✅ Stack stopped.")
	return nil
}

// waitForExit polls until pid is no longer alive or timeout elapses,
// returning whether it exited in time.
func waitForExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !processAlive(pid)
}

func processAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}
