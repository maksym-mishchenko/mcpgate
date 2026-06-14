package audit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestRecent(t *testing.T) {
	s, cleanup := tempDB(t)
	defer cleanup()

	for i := 0; i < 5; i++ {
		if err := s.Append(audit.Entry{
			Method:  "tools/call",
			Server:  "fs",
			Name:    fmt.Sprintf("tool_%d", i),
			Verdict: "ALLOW",
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	q, ok := interface{}(s).(audit.AuditQuerier)
	if !ok {
		t.Skip("store does not implement AuditQuerier")
	}
	entries, err := q.Recent(3)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("got %d entries, want 3", len(entries))
	}
	// Most recent first.
	if entries[0].Name != "tool_4" {
		t.Errorf("first entry name = %q, want tool_4", entries[0].Name)
	}
}

func TestApprovalSourceRoundTrip(t *testing.T) {
	s, cleanup := tempDB(t)
	defer cleanup()

	if err := s.Append(audit.Entry{
		Method:         "tools/call",
		Server:         "fs",
		Name:           "write_file",
		Verdict:        "DENY",
		Reason:         "timeout",
		ApprovalSource: "timeout",
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	entries, err := s.Recent(1)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if got := entries[0].ApprovalSource; got != "timeout" {
		t.Fatalf("ApprovalSource = %q, want timeout", got)
	}

	var exported bytes.Buffer
	if err := s.Export(&exported); err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(exported.String(), `"approval_source":"timeout"`) {
		t.Fatalf("export missing approval_source: %s", exported.String())
	}

	ok, err := audit.VerifyFile(&exported, nil)
	if err != nil {
		t.Fatalf("verify export: %v", err)
	}
	if !ok {
		t.Fatal("export with approval_source should verify")
	}
}

func TestHMACKeyedChain(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	store, err := audit.OpenWithHMAC(filepath.Join(dir, "test.db"), key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	for i := 0; i < 3; i++ {
		if err := store.Append(audit.Entry{
			Method:  "tools/call",
			Server:  "fs",
			Name:    fmt.Sprintf("tool_%d", i),
			Verdict: "ALLOW",
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	ok, err := store.VerifyChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("chain should be valid with correct key")
	}
}

func TestHMACWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	store, err := audit.OpenWithHMAC(filepath.Join(dir, "test.db"), key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	store.Append(audit.Entry{Method: "tools/call", Server: "fs", Name: "tool", Verdict: "ALLOW"}) //nolint:errcheck
	store.Close()

	wrongKey := make([]byte, 32)
	store2, err := audit.OpenWithHMAC(filepath.Join(dir, "test.db"), wrongKey)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store2.Close()

	ok, err := store2.VerifyChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Error("chain should fail with wrong key")
	}
}

func TestNoHMACBackwardCompatible(t *testing.T) {
	dir := t.TempDir()
	store, err := audit.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	store.Append(audit.Entry{Method: "tools/call", Server: "fs", Name: "tool", Verdict: "ALLOW"}) //nolint:errcheck

	ok, err := store.VerifyChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("non-HMAC chain should still verify")
	}
}

func TestHMACSigColumnExists(t *testing.T) {
	s, cleanup := tempDB(t)
	defer cleanup()

	// Should be able to append without error.
	if err := s.Append(audit.Entry{
		Method:  "tools/call",
		Server:  "fs",
		Name:    "read_file",
		Verdict: "ALLOW",
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	// Verify the column exists by querying it.
	var sig string
	err := s.GetDB().QueryRow(`SELECT hmac_sig FROM audit_log WHERE seq=2`).Scan(&sig)
	if err != nil {
		t.Fatalf("hmac_sig column missing or query failed: %v", err)
	}
	// Default value is empty string for non-HMAC entries.
	if sig != "" {
		t.Errorf("hmac_sig = %q, want empty for non-HMAC entry", sig)
	}
}

func TestGenesisRecordCreated(t *testing.T) {
	dir := t.TempDir()
	store, err := audit.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	// Genesis record should exist after open.
	var method, verdict string
	var seq int64
	err = store.GetDB().QueryRow(`SELECT seq, method, verdict FROM audit_log ORDER BY seq LIMIT 1`).
		Scan(&seq, &method, &verdict)
	if err != nil {
		t.Fatalf("query genesis: %v", err)
	}
	if method != "GENESIS" {
		t.Errorf("method = %q, want GENESIS", method)
	}
	if verdict != "GENESIS" {
		t.Errorf("verdict = %q, want GENESIS", verdict)
	}
}

func TestGenesisNotDuplicatedOnReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	s1, _ := audit.Open(path)
	s1.Close()

	s2, err := audit.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	var count int
	s2.GetDB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE method='GENESIS'`).Scan(&count) //nolint:errcheck
	if count != 1 {
		t.Errorf("genesis count = %d, want 1", count)
	}
}

func TestGapDetection(t *testing.T) {
	dir := t.TempDir()
	store, err := audit.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	for i := 0; i < 3; i++ {
		store.Append(audit.Entry{Method: "tools/call", Server: "fs", Name: "tool", Verdict: "ALLOW"}) //nolint:errcheck
	}

	// No gaps yet.
	hasGap, err := store.VerifyGap()
	if err != nil {
		t.Fatalf("verifygap: %v", err)
	}
	if hasGap {
		t.Error("expected no gap, got gap")
	}

	// Create a gap by deleting the middle row (seq 2 out of genesis=1,tool=2,tool=3,tool=4).
	store.GetDB().Exec(`DELETE FROM audit_log WHERE seq=3`) //nolint:errcheck

	hasGap, err = store.VerifyGap()
	if err != nil {
		t.Fatalf("verifygap: %v", err)
	}
	if !hasGap {
		t.Error("expected gap after deletion, got none")
	}
}

func TestExport(t *testing.T) {
	dir := t.TempDir()
	store, err := audit.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	for i := 0; i < 2; i++ {
		store.Append(audit.Entry{Method: "tools/call", Server: "fs", Name: fmt.Sprintf("tool_%d", i), Verdict: "ALLOW"}) //nolint:errcheck
	}

	var buf bytes.Buffer
	if err := store.Export(&buf); err != nil {
		t.Fatalf("export: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// genesis + 2 entries = 3 lines
	if len(lines) != 3 {
		t.Errorf("exported %d lines, want 3", len(lines))
	}
	// Each line must be valid JSON with a "seq" field.
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
		if _, ok := obj["seq"]; !ok {
			t.Errorf("line %d missing seq field", i)
		}
	}
}

func TestAppend_WithWarnings_VerifiesAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	s, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	e := audit.Entry{
		Method:  "resources/read",
		Server:  "s",
		Verdict: "ALLOW",
		Reason:  "policy",
		Warnings: []audit.Warning{
			{ID: "injection.ignore-previous", Severity: "high", Snippet: "ignore all previous instructions"},
		},
	}
	if err := s.Append(e); err != nil {
		t.Fatalf("append: %v", err)
	}

	ok, err := s.VerifyChain()
	if err != nil || !ok {
		t.Fatalf("verify chain ok=%v err=%v", ok, err)
	}

	recent, err := s.Recent(1)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(recent) != 1 || len(recent[0].Warnings) != 1 ||
		recent[0].Warnings[0].ID != "injection.ignore-previous" {
		t.Fatalf("warnings did not round-trip: %+v", recent)
	}
}
