// Package scanner performs deterministic, pattern-based detection of
// prompt-injection and tool-poisoning signatures in MCP traffic. It is pure:
// no I/O, no error path, panic-free.
package scanner

import "regexp"

// SignatureSetVersion identifies the compiled pattern library so audit rows
// can record which version produced a match.
const SignatureSetVersion = "1"

// maxSnippet bounds the length of a recorded match so a large payload cannot
// bloat an audit row.
const maxSnippet = 80

// Threat is a single heuristic match.
type Threat struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Snippet  string `json:"snippet"`
}

type signature struct {
	id       string
	severity string
	re       *regexp.Regexp
}

// signatures is the compiled, versioned built-in library. Patterns are
// case-insensitive. Keep these conservative to limit false positives.
var signatures = []signature{
	{"injection.ignore-previous", "high",
		regexp.MustCompile(`(?i)ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions`)},
	{"injection.jailbreak", "high",
		regexp.MustCompile(`(?i)\b(developer\s+mode|\bDAN\b|you\s+are\s+now|do\s+anything\s+now)\b`)},
	{"exfil.base64", "medium",
		regexp.MustCompile(`(?i)base64\s*\(`)},
	{"exfil.data-uri", "medium",
		regexp.MustCompile(`(?i)data:[a-z]+/[a-z0-9.+-]+;base64,`)},
	{"exfil.credential", "high",
		regexp.MustCompile(`(AKIA[0-9A-Z]{16}|-----BEGIN\s+[A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._-]{20,})`)},
}

// Scan runs every signature over text and returns zero or more matches,
// in signature-table order. Each Threat's Snippet is the first match for that
// signature, truncated to maxSnippet runes.
func Scan(text string) []Threat {
	var out []Threat
	for _, s := range signatures {
		if loc := s.re.FindString(text); loc != "" {
			out = append(out, Threat{
				ID:       s.id,
				Severity: s.severity,
				Snippet:  truncate(loc),
			})
		}
	}
	return out
}

func truncate(s string) string {
	r := []rune(s)
	if len(r) <= maxSnippet {
		return s
	}
	return string(r[:maxSnippet])
}
