package main

import (
	"os"
	"path/filepath"
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

func TestLoadOptionalSecretRejectsValueAndFile(t *testing.T) {
	_, err := loadOptionalSecret("inline", "secret.txt", "token")
	if err == nil {
		t.Fatal("expected error when both inline value and file path are set")
	}
}

func TestLoadOptionalSecretFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	got, err := loadOptionalSecret("", path, "token")
	if err != nil {
		t.Fatalf("load secret: %v", err)
	}
	if got != "secret-token" {
		t.Fatalf("token = %q, want trimmed secret-token", got)
	}
}

func TestOpenAuditStoreWithKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(keyPath, key, 0o400); err != nil {
		t.Fatalf("write key: %v", err)
	}
	store, err := openAuditStore(filepath.Join(dir, "audit.db"), keyPath)
	if err != nil {
		t.Fatalf("open audit store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close audit store: %v", err)
		}
	}()
}
