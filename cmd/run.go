package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/kelyonn/airlock/container"
	"github.com/spf13/cobra"
)

var (
	memoryLimit  string
	cpuLimit     int
	hostname     string
	volumes      []string // raw -v specs e.g. "/tmp:/data:ro"
	noSeccomp    bool
	portForwards []string // raw -p specs e.g. "8080:80"
	noNetwork    bool
	workingDir   string
	userSpec     string
	userNS       bool
	initFlag     bool
	verifyKey    string
)

var runCmd = &cobra.Command{
	Use:   "run [OPTIONS] IMAGE [COMMAND] [ARGS...]",
	Short: "Run a command inside a new container",
	Long: `Run launches a new isolated container and executes the given command inside it.
The container uses Linux namespaces, chroot, and cgroups for isolation.

The first positional argument is treated as an OCI image reference (e.g. "alpine:3.20",
"ubuntu:24.04", "ghcr.io/owner/repo:tag"). If it starts with "/" it is treated as a
bare command using the default Alpine rootfs (legacy mode).

COMMAND is optional when an image is given: with no trailing command, the
image's own ENTRYPOINT/CMD is used, the same defaults "docker run" falls
back to — so "airlock run nginx:alpine" works without spelling out
nginx's own startup command by hand.

Examples:
  airlock run nginx:alpine                    (uses the image's own ENTRYPOINT/CMD)
  airlock run alpine:3.20 /bin/sh
  airlock run ubuntu:24.04 /bin/bash -c "echo hello"
  airlock run --memory 256m --cpu 80 alpine /bin/sh
  airlock run /bin/sh                         (legacy: use default Alpine rootfs)`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Parse each -v spec into a typed VolumeMount before running.
		var mounts []container.VolumeMount
		for _, spec := range volumes {
			mount, err := container.ParseVolumeSpec(spec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: invalid volume %q: %v\n", spec, err)
				os.Exit(1)
			}
			mounts = append(mounts, mount)
		}

		// Parse port-forward specs.
		var pfs []container.PortForward
		for _, spec := range portForwards {
			parts := strings.SplitN(spec, ":", 2)
			if len(parts) != 2 {
				fmt.Fprintf(os.Stderr, "error: invalid port forward %q: expected host:container\n", spec)
				os.Exit(1)
			}
			pfs = append(pfs, container.PortForward{HostPort: parts[0], ContainerPort: parts[1]})
		}

		// Determine whether the first argument is an image reference or a legacy command.
		// A legacy command starts with "/" (e.g. /bin/sh). Everything else is treated as
		// an OCI image reference.
		var imageRef string
		var command string
		var cmdArgs []string

		if strings.HasPrefix(args[0], "/") {
			// Legacy mode: airlock run /bin/sh [args...]
			command = args[0]
			cmdArgs = args[1:]
		} else {
			// New mode: airlock run alpine:3.20 [/bin/sh [args...]]
			imageRef = args[0]
			if len(args) >= 2 {
				command = args[1]
				cmdArgs = args[2:]
			}
			// No trailing command is fine here — container.Run falls back to
			// the image's own ENTRYPOINT/CMD and errors clearly if the image
			// doesn't have one either.
		}

		config := container.Config{
			Command:       command,
			Args:          cmdArgs,
			Hostname:      hostname,
			MemoryLimit:   memoryLimit,
			CPULimit:      cpuLimit,
			Verbose:       verbose,
			Volumes:       mounts,
			NoSeccomp:     noSeccomp,
			Image:         imageRef,
			NoNetwork:     noNetwork,
			PortForwards:  pfs,
			WorkingDir:    workingDir,
			User:          userSpec,
			UserNS:        userNS,
			Init:          initFlag,
			VerifyKeyPath: verifyKey,
		}

		if err := container.Run(config); err != nil {
			// A plain non-zero exit from the container's own command isn't
			// an airlock error — mirror its exact exit code silently, the
			// way `docker run`'s own exit code matches the container's,
			// rather than printing "error:" for something the user's own
			// command did on purpose (e.g. `exit 42`) and collapsing every
			// non-zero outcome into a generic 1.
			if exitErr, ok := err.(*container.ExitError); ok {
				os.Exit(exitErr.Code)
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	runCmd.Flags().StringVarP(&memoryLimit, "memory", "m", "100m", "memory limit (e.g., 100m, 1g)")
	runCmd.Flags().IntVar(&cpuLimit, "cpu", 50, "CPU limit as percentage (1-100)")
	runCmd.Flags().StringVar(&hostname, "hostname", "airlock-container", "container hostname")
	runCmd.Flags().StringArrayVarP(&volumes, "volume", "v", nil, "bind mount a volume: host_path:container_path[:ro] (repeatable)")
	runCmd.Flags().BoolVar(&noSeccomp, "no-seccomp", false, "disable seccomp syscall filtering (for debugging)")
	runCmd.Flags().StringArrayVarP(&portForwards, "publish", "p", nil, "publish a container port: host_port:container_port (repeatable)")
	runCmd.Flags().BoolVar(&noNetwork, "no-network", false, "disable container networking")
	runCmd.Flags().StringVarP(&workingDir, "workdir", "w", "", "working directory inside the container (defaults to the image's own WORKDIR, or /)")
	runCmd.Flags().StringVarP(&userSpec, "user", "u", "", `user to run as, as "uid", "uid:gid", "name", or "name:group" (defaults to the image's own USER, or root)`)
	runCmd.Flags().BoolVar(&userNS, "userns", false, "isolate with a Linux user namespace: container root maps to an unprivileged host UID instead of real root (see README's Security model section)")
	runCmd.Flags().BoolVar(&initFlag, "init", false, "run the command under a minimal init that forwards signals and reaps zombies (like `docker run --init`); the command is no longer PID 1")
	runCmd.Flags().StringVar(&verifyKey, "verify-key", "", "require the image to have a valid cosign static-key signature from this PEM public key (cosign sign --key/verify --key compatible; not Sigstore's keyless flow) before pulling or running it")
	// Stop flag parsing after the first positional arg (the image or command).
	// Without this, `airlock run alpine /bin/sh -c "cmd"` would try to parse -c as an airlock flag.
	runCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(runCmd)
}
