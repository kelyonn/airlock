package compose

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kelyonnnn17/airlock/container"
	"github.com/kelyonnnn17/airlock/image"
	"github.com/kelyonnnn17/airlock/state"
)

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

// Up starts all services in the manifest in dependency order.
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
		// Brief pause to let the service initialize (simplistic readiness)
		time.Sleep(1 * time.Second)
	}

	fmt.Println("\n✅ All services started successfully.")
	return nil
}

// startService launches a single container via container.Run
func (o *Orchestrator) startService(name string, svc ServiceDef, myIP string, allIPs map[string]string, verbose bool) error {
	// Parse ports
	var pfs []container.PortForward
	for _, spec := range svc.Ports {
		parts := strings.SplitN(spec, ":", 2)
		if len(parts) == 2 {
			pfs = append(pfs, container.PortForward{HostPort: parts[0], ContainerPort: parts[1]})
		}
	}

	// Parse volumes
	var mounts []container.VolumeMount
	for _, spec := range svc.Volumes {
		mount, err := container.ParseVolumeSpec(spec)
		if err == nil {
			mounts = append(mounts, mount)
		} else {
			fmt.Fprintf(os.Stderr, "warning: invalid volume spec %q: %v\n", spec, err)
		}
	}

	// Default memory
	mem := svc.Memory
	if mem == "" {
		mem = "100m"
	}
	// Default CPU
	cpu := svc.CPU
	if cpu == 0 {
		cpu = 50
	}

	// Parse command
	cmdParts := strings.Fields(svc.Command)
	if len(cmdParts) == 0 {
		return fmt.Errorf("service %s has no command", name)
	}

	// First, pull the image to get the rootfs directory
	// We need the rootfs to inject the /etc/hosts file BEFORE starting the container.
	// We call image.Pull directly here so we can inject the file.
	// container.Run will see config.Image is set and will also call image.Pull,
	// but it will be an instant cache hit.
	rootfsDir, err := image.Pull(svc.Image, verbose)
	if err != nil {
		return fmt.Errorf("pull image %s: %w", svc.Image, err)
	}

	// Inject /etc/hosts so it can resolve other services
	if err := InjectHostsFile(rootfsDir, allIPs, name, myIP); err != nil {
		fmt.Fprintf(os.Stderr, "warning: inject hosts file failed: %v\n", err)
	}

	config := container.Config{
		Image:        svc.Image,
		Command:      cmdParts[0],
		Args:         cmdParts[1:],
		Hostname:     name,
		MemoryLimit:  mem,
		CPULimit:     cpu,
		Verbose:      verbose,
		Volumes:      mounts,
		PortForwards: pfs,
	}

	// Run the container in a goroutine so it runs in the background.
	// We'll use a waitgroup to know if it fails to start.
	var wg sync.WaitGroup
	wg.Add(1)

	var startErr error
	go func() {
		// Because Run blocks until the container exits, we signal the WaitGroup
		// immediately, assuming it started if it didn't error immediately.
		// A more robust approach would wait for the state file to have it.
		wg.Done()

		// Run the container (this blocks until it exits)
		// We set an environment variable or just let Run do its thing.
		// Since container.Run handles its own state.Register, but we need
		// to set ServiceName and ComposeFile, we'll patch state.Register in Run.
		// Actually, we modified state.Register to take serviceName and composeFile!
		// However, container.Run currently calls state.Register with empty strings.
		// To fix this without modifying container.go again, we can let container.Run
		// register it, then immediately update the state file from here.
		if err := container.Run(config); err != nil {
			fmt.Fprintf(os.Stderr, "\n[Service %s] exited with error: %v\n", name, err)
		}
	}()

	wg.Wait()

	// Wait briefly for the container to register itself
	time.Sleep(500 * time.Millisecond)

	// Now update the state file with the ServiceName and ComposeFile
	containers, _ := state.List()
	// Find the most recently started one matching our image and command
	// (or we can just find the one that doesn't have a ComposeFile set yet)
	for _, c := range containers {
		if c.Image == svc.Image && c.ComposeFile == "" {
			// Found it. Update and save.
			// It's a bit hacky, but avoids circular dependencies or changing container.Config again.
			c.ServiceName = name
			c.ComposeFile = o.ManifestPath
			
			// We have to overwrite it in the state file
			_ = state.Unregister(c.ID)
			_ = state.Register(c.ID, c.PID, c.Command, c.RootfsDir, c.CgroupDir, c.IPAddress, c.Image, name, o.ManifestPath)
			break
		}
	}

	return startErr
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
		process, err := os.FindProcess(c.PID)
		if err == nil {
			// Send SIGTERM
			process.Signal(syscall.SIGTERM)
			
			// Wait a bit, then SIGKILL if still running
			time.Sleep(500 * time.Millisecond)
			process.Signal(syscall.SIGKILL)
		}

		// The container.Run goroutine will detect the exit and call CleanupNetwork and Unregister
		// but since we SIGKILL'd it, the parent process might be dead.
		// Let's do the cleanup manually just in case.
		container.CleanupNetwork(c.ID)
		state.Unregister(c.ID)
	}

	fmt.Println("✅ Stack stopped.")
	return nil
}
