package audit_test

import (
	"encoding/hex"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/audit"
)

func TestCanonicalGolden(t *testing.T) {
	// These hex strings are computed once and pinned.
	// If canonical() changes, the hash chain breaks — this test will catch it.
	cases := []struct {
		input map[string]any
		want  string // SHA-256 hex of canonical(input)
	}{
		{
			map[string]any{"method": "tools/call", "server": "fs", "verdict": "ALLOW"},
			"316f890b7a0f0c4a56f1e2076d31bddb5942516ec2e9ebfb5bdb96daac500a8d",
		},
	}
	for _, c := range cases {
		if c.want == "" {
			got := hex.EncodeToString(audit.CanonicalHash(c.input))
			t.Logf("canonical hash = %s (pin this)", got)
			continue
		}
		got := hex.EncodeToString(audit.CanonicalHash(c.input))
		if got != c.want {
			t.Errorf("CanonicalHash = %s, want %s", got, c.want)
		}
	}
}
