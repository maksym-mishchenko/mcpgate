package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyFileRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

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
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

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
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

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

func TestVerifyFileWithKeyRejectsMissingHMAC(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	store, err := OpenWithHMAC(filepath.Join(dir, "test.db"), key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer closeStore(t, store)

	if err := store.Append(Entry{Method: "tools/call", Server: "fs", Name: "tool", Verdict: "ALLOW"}); err != nil {
		t.Fatalf("append: %v", err)
	}

	var buf bytes.Buffer
	if err := store.Export(&buf); err != nil {
		t.Fatalf("export: %v", err)
	}

	var stripped bytes.Buffer
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var row ExportedRow
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatalf("unmarshal export row: %v", err)
		}
		if row.Method != "GENESIS" {
			row.HMACsig = ""
		}
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatalf("marshal stripped row: %v", err)
		}
		stripped.Write(encoded)
		stripped.WriteByte('\n')
	}

	ok, err := VerifyFile(bytes.NewReader(stripped.Bytes()), key)
	if err != nil {
		t.Fatalf("verify stripped HMAC: %v", err)
	}
	if ok {
		t.Fatal("keyed verification should reject non-genesis rows with missing HMAC")
	}
}

func TestVerifyFileRejectsDeletedSignedRowWithRecomputedHashes(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	store, err := OpenWithHMAC(filepath.Join(dir, "test.db"), key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer closeStore(t, store)

	if err := store.Append(Entry{Method: "tools/call", Server: "fs", Name: "first", Verdict: "ALLOW"}); err != nil {
		t.Fatalf("append first: %v", err)
	}
	if err := store.Append(Entry{Method: "tools/call", Server: "fs", Name: "second", Verdict: "ALLOW"}); err != nil {
		t.Fatalf("append second: %v", err)
	}

	rows := exportRows(t, store)
	if len(rows) != 3 {
		t.Fatalf("export rows = %d, want 3", len(rows))
	}
	tampered := rows[:1]
	tampered = append(tampered, rows[2])
	recomputeExportHashes(t, tampered)

	ok, err := VerifyFile(bytes.NewReader(marshalRows(t, tampered)), key)
	if err != nil {
		t.Fatalf("verify tampered gap: %v", err)
	}
	if ok {
		t.Fatal("keyed verification should reject deleted rows even when public hashes are recomputed")
	}
}

func TestVerifyFileRejectsNonBootstrapGenesisHMACBypass(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	store, err := OpenWithHMAC(filepath.Join(dir, "test.db"), key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer closeStore(t, store)

	if err := store.Append(Entry{Method: "tools/call", Server: "fs", Name: "tool", Verdict: "ALLOW"}); err != nil {
		t.Fatalf("append: %v", err)
	}

	rows := exportRows(t, store)
	rows[1].Method = "GENESIS"
	recomputeExportHashes(t, rows)

	ok, err := VerifyFile(bytes.NewReader(marshalRows(t, rows)), key)
	if err != nil {
		t.Fatalf("verify forged genesis: %v", err)
	}
	if ok {
		t.Fatal("keyed verification should reject non-bootstrap GENESIS rows")
	}
}

func exportRows(t *testing.T, store *SQLiteStore) []ExportedRow {
	t.Helper()
	var buf bytes.Buffer
	if err := store.Export(&buf); err != nil {
		t.Fatalf("export: %v", err)
	}
	var rows []ExportedRow
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var row ExportedRow
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatalf("unmarshal row: %v", err)
		}
		rows = append(rows, row)
	}
	return rows
}

func marshalRows(t *testing.T, rows []ExportedRow) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatalf("marshal row: %v", err)
		}
		buf.Write(encoded)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func recomputeExportHashes(t *testing.T, rows []ExportedRow) {
	t.Helper()
	prevHash := ""
	for i := range rows {
		ts, err := time.Parse(time.RFC3339, rows[i].Ts)
		if err != nil {
			t.Fatalf("parse ts: %v", err)
		}
		fields := map[string]any{
			"method":  rows[i].Method,
			"server":  rows[i].Server,
			"name":    rows[i].Name,
			"args":    rows[i].Args,
			"verdict": rows[i].Verdict,
			"reason":  rows[i].Reason,
			"seq":     rows[i].Seq,
			"ts":      ts.Unix(),
		}
		if rows[i].Warnings != "" {
			fields["warnings"] = rows[i].Warnings
		}
		if rows[i].ApprovalSource != "" {
			fields["approval_source"] = rows[i].ApprovalSource
		}
		entryBytes := canonicalJSON(fields)
		h := sha256.Sum256(append([]byte(prevHash), entryBytes...))
		rows[i].Hash = hex.EncodeToString(h[:])
		prevHash = rows[i].Hash
	}
}

func closeStore(t *testing.T, store *SQLiteStore) func() {
	t.Helper()
	return func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}
}
