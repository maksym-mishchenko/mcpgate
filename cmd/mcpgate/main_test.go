package main

import (
	"strings"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/policy"
)

func TestSelectConfiguredServerSingle(t *testing.T) {
	servers := map[string]policy.ServerConfig{
		"filesystem": {Command: []string{"mcp-filesystem"}},
	}

	name, srv, err := selectConfiguredServer(servers, "")
	if err != nil {
		t.Fatalf("selectConfiguredServer: %v", err)
	}
	if name != "filesystem" {
		t.Fatalf("name = %q, want filesystem", name)
	}
	if got := srv.TransportKind(); got != "stdio" {
		t.Fatalf("transport = %q, want stdio", got)
	}
}

func TestSelectConfiguredServerRequested(t *testing.T) {
	servers := map[string]policy.ServerConfig{
		"filesystem": {Command: []string{"mcp-filesystem"}},
		"github":     {URL: "http://127.0.0.1:9000"},
	}

	name, srv, err := selectConfiguredServer(servers, "github")
	if err != nil {
		t.Fatalf("selectConfiguredServer: %v", err)
	}
	if name != "github" {
		t.Fatalf("name = %q, want github", name)
	}
	if got := srv.TransportKind(); got != "http" {
		t.Fatalf("transport = %q, want http", got)
	}
}

func TestSelectConfiguredServerRequiresExplicitChoiceForMultipleServers(t *testing.T) {
	servers := map[string]policy.ServerConfig{
		"zeta":  {Command: []string{"zeta"}},
		"alpha": {Command: []string{"alpha"}},
	}

	_, _, err := selectConfiguredServer(servers, "")
	if err == nil {
		t.Fatal("expected ambiguous multi-server error, got nil")
	}
	if !strings.Contains(err.Error(), "alpha, zeta") {
		t.Fatalf("error = %q, want sorted server names", err)
	}
}

func TestSelectConfiguredServerRejectsUnknownRequestedServer(t *testing.T) {
	servers := map[string]policy.ServerConfig{
		"filesystem": {Command: []string{"mcp-filesystem"}},
	}

	_, _, err := selectConfiguredServer(servers, "missing")
	if err == nil {
		t.Fatal("expected unknown server error, got nil")
	}
	if !strings.Contains(err.Error(), `server "missing" not found`) {
		t.Fatalf("error = %q, want missing server message", err)
	}
}
