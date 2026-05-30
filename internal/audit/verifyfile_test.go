package audit

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestVerifyFileRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	store.Append(Entry{Method: "tools/call", Server: "fs", Name: "tool", Verdict: "ALLOW"}) //nolint:errcheck

	var buf bytes.Buffer
	if err := store.Export(&buf); err != nil {
		t.Fatalf("export: %v", err)
	}

	ok, err := VerifyFile(&buf, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("expected chain to verify OK after roundtrip")
	}
}

func TestVerifyFileTamperedFails(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	store.Append(Entry{Method: "tools/call", Server: "fs", Name: "tool", Verdict: "ALLOW"}) //nolint:errcheck

	var buf bytes.Buffer
	store.Export(&buf) //nolint:errcheck

	// Tamper: replace ALLOW with DENY in the export.
	tampered := bytes.ReplaceAll(buf.Bytes(), []byte(`"ALLOW"`), []byte(`"DENY"`))

	ok, err := VerifyFile(bytes.NewReader(tampered), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Error("tampered chain should fail verification")
	}
}

func TestVerifyFileHMACRoundtrip(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	store, err := OpenWithHMAC(filepath.Join(dir, "test.db"), key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	store.Append(Entry{Method: "tools/call", Server: "fs", Name: "tool", Verdict: "ALLOW"}) //nolint:errcheck

	var buf bytes.Buffer
	store.Export(&buf) //nolint:errcheck

	ok, err := VerifyFile(bytes.NewReader(buf.Bytes()), key)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("HMAC chain should verify with correct key")
	}

	// Wrong key should fail.
	wrongKey := make([]byte, 32)
	ok2, err := VerifyFile(bytes.NewReader(buf.Bytes()), wrongKey)
	if err != nil {
		t.Fatalf("verify wrong key: %v", err)
	}
	if ok2 {
		t.Error("HMAC chain should fail with wrong key")
	}
}
