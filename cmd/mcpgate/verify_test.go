package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/audit"
)

func TestRunVerifyCleanChain(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	exportPath := filepath.Join(dir, "export.jsonl")

	store, _ := audit.Open(dbPath)
	store.Append(audit.Entry{Method: "tools/call", Server: "fs", Name: "tool", Verdict: "ALLOW"}) //nolint:errcheck

	f, _ := os.Create(exportPath)
	store.Export(f) //nolint:errcheck
	f.Close()
	store.Close()

	if err := runVerify(exportPath, ""); err != nil {
		t.Fatalf("runVerify: %v", err)
	}
}
