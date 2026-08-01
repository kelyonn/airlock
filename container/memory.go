// No build tag — parseMemoryLimit is pure string parsing used by
// container/cgroups.go (linux-only) but kept in an untagged file so it's
// unit-testable on any platform, the same reasoning applied to volumes.go
// and config.go.

package container

import (
	"fmt"
	"strconv"
	"strings"
)

// parseMemoryLimit converts a human-readable memory limit to bytes.
// Supports: "100m", "256m", "1g", "512k", or raw bytes as a number.
func parseMemoryLimit(limit string) (int64, error) {
	limit = strings.TrimSpace(strings.ToLower(limit))
	if limit == "" {
		return 100 * 1024 * 1024, nil // default 100MB
	}

	var multiplier int64 = 1
	numStr := limit

	if strings.HasSuffix(limit, "g") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(limit, "g")
	} else if strings.HasSuffix(limit, "m") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(limit, "m")
	} else if strings.HasSuffix(limit, "k") {
		multiplier = 1024
		numStr = strings.TrimSuffix(limit, "k")
	}

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse '%s': %w", limit, err)
	}

	return num * multiplier, nil
}
