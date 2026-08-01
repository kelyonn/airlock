// Package shellwords tokenizes a shell-like command string into argv,
// honoring single quotes, double quotes, and backslash escapes.
//
// It exists because compose manifests write commands the way you'd type
// them at a shell — e.g. `nginx -g "daemon off;"` — and a naive
// strings.Fields split breaks that into ["nginx", "-g", `"daemon`, `off;"`],
// which is not what nginx receives as argv. This is not a full POSIX shell
// lexer (no variable expansion, globbing, or command substitution — none of
// which apply to a static argv list anyway); it only needs to solve
// quoting.
package shellwords

import (
	"fmt"
	"strings"
)

// Split tokenizes s into argv-style fields.
func Split(s string) ([]string, error) {
	var (
		args               []string
		cur                strings.Builder
		inSingle, inDouble bool
		hasToken           bool
	)

	flush := func() {
		if hasToken {
			args = append(args, cur.String())
			cur.Reset()
			hasToken = false
		}
	}

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case inSingle:
			if r == '\'' {
				inSingle = false
			} else {
				cur.WriteRune(r)
			}

		case inDouble:
			switch {
			case r == '"':
				inDouble = false
			case r == '\\' && i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\\'):
				i++
				cur.WriteRune(runes[i])
			default:
				cur.WriteRune(r)
			}

		case r == '\'':
			inSingle = true
			hasToken = true

		case r == '"':
			inDouble = true
			hasToken = true

		case r == '\\':
			if i+1 < len(runes) {
				i++
				cur.WriteRune(runes[i])
				hasToken = true
			}

		case r == ' ' || r == '\t' || r == '\n':
			flush()

		default:
			cur.WriteRune(r)
			hasToken = true
		}
	}

	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote in command: %q", s)
	}
	flush()

	return args, nil
}
