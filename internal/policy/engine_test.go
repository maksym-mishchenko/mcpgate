package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func ptrFloat(v float64) *float64 { return &v }

func ptrBool(v bool) *bool { return &v }

func rawArgs(values map[string]string) policy.Args {
	args := make(policy.Args, len(values))
	for k, v := range values {
		args[k] = json.RawMessage(v)
	}
	return args
}

func TestVerdictMatrix(t *testing.T) {
	cases := []struct {
		server, method, name string
		args                 map[string]string
		want                 policy.Verdict
	}{
		{"fs", "tools/call", "read_file", map[string]string{"path": "/home/safe/a.txt"}, policy.VerdictAllow},
		{"fs", "tools/call", "read_file", map[string]string{"path": "/etc/passwd"}, policy.VerdictDeny},
		{"fs", "tools/call", "write_file", nil, policy.VerdictDeny},
		{"fs", "tools/call", "exec", nil, policy.VerdictAsk},
		{"fs", "tools/call", "unknown_tool", nil, policy.VerdictUnknown},
		{"other", "tools/call", "x", nil, policy.VerdictUnknown},
		{"fs", "resources/read", "file:///etc/passwd", nil, policy.VerdictUnknown},
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

func TestFieldConstraintsUseJSONTypes(t *testing.T) {
	cfg := &policy.Config{
		Version: 1,
		Mode:    "enforce",
		Default: policy.AllowFalse,
		Servers: map[string]policy.ServerConfig{
			"fs": {
				Command: []string{"echo"},
				Tools: map[string]policy.TargetRule{
					"search": {
						Allow: policy.AllowTrue,
						Constraints: &policy.Constraints{
							Fields: map[string]policy.FieldConstraint{
								"mode":   {Equals: "exact"},
								"limit":  {Min: ptrFloat(1), Max: ptrFloat(20)},
								"hidden": {Bool: ptrBool(false)},
							},
						},
					},
				},
			},
		},
	}

	got := policy.EvaluateArgs("fs", "tools/call", "search", rawArgs(map[string]string{
		"mode":   `"exact"`,
		"limit":  `10`,
		"hidden": `false`,
	}), cfg)
	if got != policy.VerdictAllow {
		t.Fatalf("EvaluateArgs with typed JSON = %v, want %v", got, policy.VerdictAllow)
	}

	got = policy.EvaluateArgs("fs", "tools/call", "search", rawArgs(map[string]string{
		"mode":   `{"nested":"exact"}`,
		"limit":  `10`,
		"hidden": `false`,
	}), cfg)
	if got != policy.VerdictDeny {
		t.Fatalf("object string constraint = %v, want %v", got, policy.VerdictDeny)
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

func TestPathConstraintMissingPathDenies(t *testing.T) {
	c := cfg()
	got := policy.Evaluate("fs", "tools/call", "read_file", map[string]string{}, c)
	if got != policy.VerdictDeny {
		t.Errorf("missing path under path constraint: got %v, want deny", got)
	}
}

func TestWithinRelativePathDenies(t *testing.T) {
	c := cfg()
	got := policy.Evaluate("fs", "tools/call", "read_file",
		map[string]string{"path": "home/safe/a.txt"}, c)
	if got != policy.VerdictDeny {
		t.Errorf("relative path: got %v, want deny", got)
	}
}

func TestWithinCleanPathRequired(t *testing.T) {
	c := cfg()
	got := policy.Evaluate("fs", "tools/call", "read_file",
		map[string]string{"path": "/home/safe//a.txt"}, c)
	if got != policy.VerdictDeny {
		t.Errorf("non-clean path: got %v, want deny", got)
	}
}

func TestSamplingAllow(t *testing.T) {
	cfg := &policy.Config{
		Version: 1,
		Mode:    "enforce",
		Servers: map[string]policy.ServerConfig{
			"myserver": {
				Command:  []string{"mcp-server"},
				Sampling: &policy.SamplingRule{Allow: true},
			},
		},
	}
	v := policy.Evaluate("myserver", "sampling/createMessage", "", nil, cfg)
	if v != policy.VerdictAllow {
		t.Errorf("expected ALLOW, got %v", v)
	}
}

func TestSamplingDefaultDeny(t *testing.T) {
	cfg := &policy.Config{
		Version: 1,
		Mode:    "enforce",
		Servers: map[string]policy.ServerConfig{
			"myserver": {
				Command: []string{"mcp-server"},
			},
		},
	}
	v := policy.Evaluate("myserver", "sampling/createMessage", "", nil, cfg)
	if v != policy.VerdictDeny {
		t.Errorf("expected DENY, got %v", v)
	}
}

func TestPromptsAllow(t *testing.T) {
	cfg := &policy.Config{
		Version: 1,
		Mode:    "enforce",
		Servers: map[string]policy.ServerConfig{
			"myserver": {
				Command: []string{"mcp-server"},
				Prompts: &policy.PromptsRule{Allow: true},
			},
		},
	}
	v := policy.Evaluate("myserver", "prompts/get", "my-prompt", nil, cfg)
	if v != policy.VerdictAllow {
		t.Errorf("expected ALLOW, got %v", v)
	}
}

func TestPromptsDefaultDeny(t *testing.T) {
	cfg := &policy.Config{
		Version: 1,
		Mode:    "enforce",
		Servers: map[string]policy.ServerConfig{
			"myserver": {
				Command: []string{"mcp-server"},
			},
		},
	}
	v := policy.Evaluate("myserver", "prompts/get", "my-prompt", nil, cfg)
	if v != policy.VerdictDeny {
		t.Errorf("expected DENY, got %v", v)
	}
}

func TestFieldConstraints(t *testing.T) {
	cfg := &policy.Config{
		Version: 1,
		Mode:    "enforce",
		Default: policy.AllowFalse,
		Servers: map[string]policy.ServerConfig{
			"fs": {
				Command: []string{"echo"},
				Tools: map[string]policy.TargetRule{
					"search": {
						Allow: policy.AllowTrue,
						Constraints: &policy.Constraints{
							Fields: map[string]policy.FieldConstraint{
								"mode":   {OneOf: []string{"exact", "fuzzy"}},
								"limit":  {Min: ptrFloat(1), Max: ptrFloat(20)},
								"hidden": {Bool: ptrBool(false)},
								"query":  {Matches: `[a-z]+`},
							},
						},
					},
				},
			},
		},
	}

	cases := []struct {
		name string
		args map[string]string
		want policy.Verdict
	}{
		{
			name: "allow matching fields",
			args: map[string]string{"mode": "exact", "limit": "10", "hidden": "false", "query": "notes"},
			want: policy.VerdictAllow,
		},
		{
			name: "deny enum mismatch",
			args: map[string]string{"mode": "regex", "limit": "10", "hidden": "false", "query": "notes"},
			want: policy.VerdictDeny,
		},
		{
			name: "deny numeric range mismatch",
			args: map[string]string{"mode": "exact", "limit": "99", "hidden": "false", "query": "notes"},
			want: policy.VerdictDeny,
		},
		{
			name: "deny invalid bool",
			args: map[string]string{"mode": "exact", "limit": "10", "hidden": "maybe", "query": "notes"},
			want: policy.VerdictDeny,
		},
		{
			name: "deny missing constrained field",
			args: map[string]string{"mode": "exact", "limit": "10", "hidden": "false"},
			want: policy.VerdictDeny,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.Evaluate("fs", "tools/call", "search", tc.args, cfg)
			if got != tc.want {
				t.Fatalf("Evaluate = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveWithinPathConstraint(t *testing.T) {
	dir := t.TempDir()
	safe := filepath.Join(dir, "safe")
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(safe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	safeTarget := filepath.Join(safe, "allowed.txt")
	outsideTarget := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(safeTarget, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideTarget, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	insideLink := filepath.Join(safe, "inside-link")
	outsideLink := filepath.Join(safe, "outside-link")
	if err := os.Symlink(safeTarget, insideLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideTarget, outsideLink); err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Version: 1,
		Mode:    "enforce",
		Servers: map[string]policy.ServerConfig{
			"fs": {
				Command: []string{"echo"},
				Tools: map[string]policy.TargetRule{
					"read_file": {
						Allow: policy.AllowTrue,
						Constraints: &policy.Constraints{
							Path: &policy.PathConstraint{ResolveWithin: []string{safe}},
						},
					},
				},
			},
		},
	}
	cfgMissingRoot := &policy.Config{
		Version: 1,
		Mode:    "enforce",
		Servers: map[string]policy.ServerConfig{
			"fs": {
				Command: []string{"echo"},
				Tools: map[string]policy.TargetRule{
					"read_file": {
						Allow: policy.AllowTrue,
						Constraints: &policy.Constraints{
							Path: &policy.PathConstraint{ResolveWithin: []string{filepath.Join(dir, "missing-root")}},
						},
					},
				},
			},
		},
	}

	cases := []struct {
		name string
		path string
		want policy.Verdict
	}{
		{name: "direct file", path: safeTarget, want: policy.VerdictAllow},
		{name: "symlink within safe root", path: insideLink, want: policy.VerdictAllow},
		{name: "symlink escaping safe root", path: outsideLink, want: policy.VerdictDeny},
		{name: "missing file fails closed", path: filepath.Join(safe, "missing.txt"), want: policy.VerdictDeny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.Evaluate("fs", "tools/call", "read_file", map[string]string{"path": tc.path}, cfg)
			if got != tc.want {
				t.Fatalf("Evaluate = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("missing root fails closed", func(t *testing.T) {
		got := policy.Evaluate("fs", "tools/call", "read_file", map[string]string{"path": safeTarget}, cfgMissingRoot)
		if got != policy.VerdictDeny {
			t.Fatalf("Evaluate = %v, want %v", got, policy.VerdictDeny)
		}
	})
}
