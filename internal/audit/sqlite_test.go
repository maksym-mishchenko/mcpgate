package audit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/audit"
)

func tempDB(t *testing.T) (*audit.SQLiteStore, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "audit*")
	if err != nil {
		t.Fatal(err)
	}
	s, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	return s, func() {
		s.Close()
		os.RemoveAll(dir)
	}
}

func TestAppendAndVerify(t *testing.T) {
	s, cleanup := tempDB(t)
	defer cleanup()

	for i := 0; i < 5; i++ {
		if err := s.Append(audit.Entry{
			Method:  "tools/call",
			Server:  "fs",
			Name:    "read_file",
			Verdict: "ALLOW",
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	ok, err := s.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !ok {
		t.Error("VerifyChain = false on untampered chain")
	}
}

func TestTamperDetection(t *testing.T) {
	s, cleanup := tempDB(t)
	defer cleanup()

	s.Append(audit.Entry{Method: "tools/call", Server: "fs", Name: "x", Verdict: "ALLOW"})
	s.Append(audit.Entry{Method: "tools/call", Server: "fs", Name: "y", Verdict: "DENY"})

	// Directly corrupt a row in the DB.
	s.TestCorruptRow(1, "DENY") // tamper: change verdict of row 1

	ok, err := s.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if ok {
		t.Error("VerifyChain = true on tampered chain — tamper not detected")
	}
}

func TestWriteFailureDenies(t *testing.T) {
	s, cleanup := tempDB(t)
	defer cleanup()

	s.InjectWriteError(true) // force next Append to fail

	err := s.Append(audit.Entry{Method: "tools/call", Verdict: "ALLOW"})
	if err == nil {
		t.Error("expected error from injected write failure")
	}
}
