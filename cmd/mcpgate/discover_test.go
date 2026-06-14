package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/audit"
	"github.com/maksym-mishchenko/mcpgate/internal/policy"
)

func TestDiscoverPolicySkipsWarningsAndDeniedRows(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		`{"seq":1,"method":"GENESIS","server":"","name":"go","args":"","verdict":"GENESIS","reason":"startup","ts":"2026-06-14T00:00:00Z","hash":"h","hmac_sig":""}`,
		`{"seq":2,"method":"tools/call","server":"fs","name":"read_file","args":"{}","verdict":"ALLOW","reason":"policy","ts":"2026-06-14T00:00:01Z","hash":"h","hmac_sig":""}`,
		`{"seq":3,"method":"tools/call","server":"fs","name":"delete_file","args":"{}","verdict":"DENY","reason":"policy","ts":"2026-06-14T00:00:02Z","hash":"h","hmac_sig":""}`,
		`{"seq":4,"method":"resources/read","server":"fs","name":"","args":"{}","verdict":"ALLOW","reason":"policy","ts":"2026-06-14T00:00:03Z","hash":"h","hmac_sig":"","warnings":"[{\"id\":\"prompt-injection\"}]"}`,
		`{"seq":5,"method":"prompts/get","server":"fs","name":"prompt","args":"{}","verdict":"ALLOW","reason":"policy","ts":"2026-06-14T00:00:04Z","hash":"h","hmac_sig":""}`,
		`{"seq":6,"method":"unknown/method","server":"empty","name":"","args":"{}","verdict":"ALLOW","reason":"policy","ts":"2026-06-14T00:00:05Z","hash":"h","hmac_sig":""}`,
		``,
	}, "\n"))

	result, err := discoverPolicy(input)
	if err != nil {
		t.Fatalf("discoverPolicy: %v", err)
	}
	if result.allowedRows != 2 {
		t.Fatalf("allowedRows = %d, want 2", result.allowedRows)
	}
	if result.skippedWarnings != 1 {
		t.Fatalf("skippedWarnings = %d, want 1", result.skippedWarnings)
	}
	if _, ok := result.servers["empty"]; ok {
		t.Fatal("unsupported allowed rows should not create empty server stubs")
	}

	var out bytes.Buffer
	if err := writeDraftPolicy(&out, result); err != nil {
		t.Fatalf("writeDraftPolicy: %v", err)
	}
	draft := out.String()
	if !strings.Contains(draft, `"read_file":`) {
		t.Fatalf("draft missing read_file: %s", draft)
	}
	if strings.Contains(draft, "delete_file") {
		t.Fatalf("draft should not include denied tool: %s", draft)
	}
	if strings.Contains(draft, "resources:\n      allow: \"true\"") {
		t.Fatalf("draft should not allow warning-tainted resources/read: %s", draft)
	}
	if !strings.Contains(draft, "prompts:\n      allow: true") {
		t.Fatalf("draft missing prompts allow: %s", draft)
	}
}

func TestRunDiscoverProducesLoadablePolicy(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	exportPath := filepath.Join(dir, "audit.jsonl")
	draftPath := filepath.Join(dir, "draft.yaml")

	store, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	if err := store.Append(audit.Entry{
		Method:  "tools/call",
		Server:  "fs",
		Name:    "read_file",
		Verdict: "ALLOW",
		Reason:  "policy",
	}); err != nil {
		t.Fatalf("append tool: %v", err)
	}
	if err := store.Append(audit.Entry{
		Method:  "resources/read",
		Server:  "fs",
		Verdict: "ALLOW",
		Reason:  "policy",
	}); err != nil {
		t.Fatalf("append resource: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	if err := runExport(dbPath, exportPath); err != nil {
		t.Fatalf("runExport: %v", err)
	}
	if err := runDiscover(exportPath, draftPath); err != nil {
		t.Fatalf("runDiscover: %v", err)
	}

	cfg, err := policy.Load(draftPath)
	if err != nil {
		data, _ := os.ReadFile(draftPath)
		t.Fatalf("load draft policy: %v\n%s", err, data)
	}
	if cfg.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", cfg.Mode)
	}
	if got := cfg.Servers["fs"].Tools["read_file"].Allow; got != policy.AllowTrue {
		t.Fatalf("read_file allow = %q, want true", got)
	}
	if got := cfg.Servers["fs"].Resources.Allow; got != policy.AllowTrue {
		t.Fatalf("resources allow = %q, want true", got)
	}
}

func TestDiscoverPolicyRequiresAllowedRows(t *testing.T) {
	_, err := discoverPolicy(strings.NewReader(`{"method":"tools/call","server":"fs","name":"x","verdict":"DENY"}`))
	if err == nil {
		t.Fatal("expected error for export with no allowed rows")
	}
}
