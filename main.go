package main

import (
	"fmt"
	"os"

	"github.com/kelyonnnn17/airlock/cmd"
	"github.com/kelyonnnn17/airlock/container"
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

	cmd.Execute()
}
