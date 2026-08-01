package compose

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kelyonn/airlock/container"
)

// RunServiceFromConfigFile is the entry point for the hidden
// "airlock __compose-service <config-file>" subcommand — the detached
// process a compose stack's containers actually run as (see main.go's
// dispatch and Orchestrator.launchDetached). It reads a container.Config
// serialized as JSON by the orchestrator, removes the now-unneeded temp
// file, and runs the container exactly as a plain `airlock run` would.
func RunServiceFromConfigFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read service config: %w", err)
	}
	os.Remove(path)

	var config container.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parse service config: %w", err)
	}

	return container.Run(config)
}
