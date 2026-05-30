package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeygenCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.key")
	if err := runKeygen(path); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 32 {
		t.Errorf("size = %d, want 32", info.Size())
	}
	// mode 0400 (read-only for owner)
	if info.Mode().Perm() != 0400 {
		t.Errorf("mode = %o, want 400", info.Mode().Perm())
	}
}

func TestKeygenExistingFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.key")
	os.WriteFile(path, []byte("existing"), 0600) //nolint:errcheck
	if err := runKeygen(path); err == nil {
		t.Error("expected error for existing file, got nil")
	}
}
