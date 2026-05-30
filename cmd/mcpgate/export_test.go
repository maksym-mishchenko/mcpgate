package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/audit"
)

func TestRunExport(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	outPath := filepath.Join(dir, "export.jsonl")

	store, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	store.Append(audit.Entry{Method: "tools/call", Server: "fs", Name: "tool", Verdict: "ALLOW"}) //nolint:errcheck
	store.Close()

	if err := runExport(dbPath, outPath); err != nil {
		t.Fatalf("runExport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), `"GENESIS"`) {
		t.Error("export missing GENESIS row")
	}
	if !strings.Contains(string(data), `"ALLOW"`) {
		t.Error("export missing ALLOW entry")
	}
}
