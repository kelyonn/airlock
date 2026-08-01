// No build tag — mergeEnv is pure string manipulation, kept in an untagged
// file so it's unit-testable on any platform (the same reasoning applied to
// volumes.go, config.go, and memory.go).

package container

import "strings"

// mergeEnv combines an image's own ENV entries with user-supplied ones,
// with user entries overriding an image entry of the same key. Order is
// preserved: image entries keep their original position (with an
// overridden value swapped in place), and any user keys the image didn't
// already define are appended after.
func mergeEnv(imageEnv, userEnv []string) []string {
	userValues := make(map[string]string, len(userEnv))
	userSeen := make(map[string]bool, len(userEnv))
	for _, kv := range userEnv {
		key, val, ok := splitEnvKV(kv)
		if !ok {
			continue
		}
		userValues[key] = val
		userSeen[key] = false // "not yet emitted" — flips true once merged in
	}

	merged := make([]string, 0, len(imageEnv)+len(userEnv))
	for _, kv := range imageEnv {
		key, _, ok := splitEnvKV(kv)
		if !ok {
			merged = append(merged, kv)
			continue
		}
		if val, overridden := userValues[key]; overridden {
			merged = append(merged, key+"="+val)
			userSeen[key] = true
		} else {
			merged = append(merged, kv)
		}
	}

	// Append user-only keys the image didn't already define, in their
	// original order.
	for _, kv := range userEnv {
		key, _, ok := splitEnvKV(kv)
		if !ok {
			merged = append(merged, kv)
			continue
		}
		if !userSeen[key] {
			merged = append(merged, kv)
			userSeen[key] = true
		}
	}

	return merged
}

// splitEnvKV splits a "KEY=VALUE" string into its parts. ok is false for a
// malformed entry with no "=".
func splitEnvKV(kv string) (key, val string, ok bool) {
	idx := strings.Index(kv, "=")
	if idx == -1 {
		return "", "", false
	}
	return kv[:idx], kv[idx+1:], true
}
