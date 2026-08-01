package main

import (
	"fmt"
	"os"

	"github.com/kelyonn/airlock/cmd"
	"github.com/kelyonn/airlock/compose"
	"github.com/kelyonn/airlock/container"
)

func main() {
	// If this binary was re-executed with "child" as the first arg,
	// we are inside the new namespaces. Skip Cobra and run child setup.
	if len(os.Args) > 1 && os.Args[1] == "child" {
		if err := container.Child(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "container error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// "__compose-service" is the hidden entry point a compose stack's
	// containers actually run as: a detached subprocess launched by the
	// orchestrator (see compose/orchestrator.go's launchDetached), reading
	// its container.Config from the file at os.Args[2].
	if len(os.Args) > 2 && os.Args[1] == "__compose-service" {
		if err := compose.RunServiceFromConfigFile(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "container error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	cmd.Execute()
}
