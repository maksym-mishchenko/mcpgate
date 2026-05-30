package policy_test

import (
	"os"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/policy"
)

const sampleYAML = `
version: 1
mode: observe
default: deny

servers:
  filesystem:
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/safe"]
    tools:
      read_file:
        allow: "true"
        constraints:
          path:
            within: ["/tmp/safe"]
      write_file:
        allow: "false"
    resources:
      allow: "ask"
`

func TestLoadConfig(t *testing.T) {
	f, err := os.CreateTemp("", "policy*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(sampleYAML)
	f.Close()

	cfg, err := policy.Load(f.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mode != "observe" {
		t.Errorf("Mode = %q, want observe", cfg.Mode)
	}
	srv, ok := cfg.Servers["filesystem"]
	if !ok {
		t.Fatal("filesystem server missing")
	}
	if len(srv.Command) == 0 {
		t.Error("command empty")
	}
	tool, ok := srv.Tools["read_file"]
	if !ok {
		t.Fatal("read_file missing")
	}
	if tool.Allow != policy.AllowTrue {
		t.Errorf("read_file allow = %v", tool.Allow)
	}
	if tool.Constraints == nil || tool.Constraints.Path == nil {
		t.Error("path constraints missing")
	}
}

func TestServerConfigURL(t *testing.T) {
	cfg := policy.ServerConfig{
		URL:         "http://localhost:8080/mcp",
		EgressAllow: []string{"localhost"},
	}
	if cfg.TransportKind() != "http" {
		t.Errorf("TransportKind = %q, want http", cfg.TransportKind())
	}
}

func TestServerConfigCommand(t *testing.T) {
	cfg := policy.ServerConfig{
		Command: []string{"mcp-filesystem"},
	}
	if cfg.TransportKind() != "stdio" {
		t.Errorf("TransportKind = %q, want stdio", cfg.TransportKind())
	}
}

func TestServerConfigNeitherErrors(t *testing.T) {
	cfg := policy.ServerConfig{}
	if kind := cfg.TransportKind(); kind != "" {
		t.Errorf("TransportKind = %q, want empty for unconfigured", kind)
	}
}
