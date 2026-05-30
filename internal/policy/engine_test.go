package policy_test

import (
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/policy"
)

func cfg() *policy.Config {
	return &policy.Config{
		Version: 1,
		Mode:    "enforce",
		Default: policy.AllowAsk,
		Servers: map[string]policy.ServerConfig{
			"fs": {
				Command: []string{"echo"},
				Tools: map[string]policy.TargetRule{
					"read_file": {
						Allow: policy.AllowTrue,
						Constraints: &policy.Constraints{
							Path: &policy.PathConstraint{
								Within: []string{"/home/safe"},
							},
						},
					},
					"write_file": {Allow: policy.AllowFalse},
					"exec":       {Allow: policy.AllowAsk},
				},
			},
		},
	}
}

func TestVerdictMatrix(t *testing.T) {
	cases := []struct {
		server, method, name string
		args                 map[string]string
		want                 policy.Verdict
	}{
		// tools/call
		{"fs", "tools/call", "read_file", map[string]string{"path": "/home/safe/a.txt"}, policy.VerdictAllow},
		{"fs", "tools/call", "read_file", map[string]string{"path": "/etc/passwd"}, policy.VerdictDeny},
		{"fs", "tools/call", "write_file", nil, policy.VerdictDeny},
		{"fs", "tools/call", "exec", nil, policy.VerdictAsk},
		{"fs", "tools/call", "unknown_tool", nil, policy.VerdictUnknown},
		// unknown server → deny-by-default (config.Default=ask here → unknown)
		{"other", "tools/call", "x", nil, policy.VerdictUnknown},
		// resources/read — not configured → default
		{"fs", "resources/read", "file:///etc/passwd", nil, policy.VerdictUnknown},
		// observe mode → always allow
	}
	c := cfg()
	for _, tc := range cases {
		got := policy.Evaluate(tc.server, tc.method, tc.name, tc.args, c)
		if got != tc.want {
			t.Errorf("Evaluate(%q,%q,%q,%v) = %v, want %v",
				tc.server, tc.method, tc.name, tc.args, got, tc.want)
		}
	}
}

func TestObserveModeAlwaysAllows(t *testing.T) {
	c := cfg()
	c.Mode = "observe"
	got := policy.Evaluate("fs", "tools/call", "write_file", nil, c)
	if got != policy.VerdictAllow {
		t.Errorf("observe mode: got %v, want VerdictAllow", got)
	}
}

func TestWithinPathComponent(t *testing.T) {
	c := cfg()
	// Prefix-as-string: "/home/safe-evil" must NOT pass "/home/safe" within check.
	got := policy.Evaluate("fs", "tools/call", "read_file",
		map[string]string{"path": "/home/safe-evil/x"}, c)
	if got != policy.VerdictDeny {
		t.Errorf("path component check: got %v, want deny", got)
	}
}

func TestWithinDotDot(t *testing.T) {
	c := cfg()
	got := policy.Evaluate("fs", "tools/call", "read_file",
		map[string]string{"path": "/home/safe/../etc/passwd"}, c)
	if got != policy.VerdictDeny {
		t.Errorf("dot-dot path: got %v, want deny", got)
	}
}

func TestWithinRelativePath(t *testing.T) {
	c := cfg()
	got := policy.Evaluate("fs", "tools/call", "read_file",
		map[string]string{"path": "relative/path"}, c)
	if got != policy.VerdictDeny {
		t.Errorf("relative path: got %v, want deny", got)
	}
}
