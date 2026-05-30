package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/maksym-mishchenko/mcpgate/internal/approval"
	"github.com/maksym-mishchenko/mcpgate/internal/audit"
	"github.com/maksym-mishchenko/mcpgate/internal/policy"
	"github.com/maksym-mishchenko/mcpgate/internal/proxy"
	"github.com/maksym-mishchenko/mcpgate/internal/transport"
)

// fakeAudit records calls but never errors.
type fakeAudit struct{ entries []audit.Entry }

func (f *fakeAudit) Append(e audit.Entry) error { f.entries = append(f.entries, e); return nil }
func (f *fakeAudit) VerifyChain() (bool, error)  { return true, nil }
func (f *fakeAudit) Close() error                { return nil }

// fakeFailAudit always errors.
type fakeFailAudit struct{}

func (f *fakeFailAudit) Append(_ audit.Entry) error { return fmt.Errorf("disk full") }
func (f *fakeFailAudit) VerifyChain() (bool, error)  { return true, nil }
func (f *fakeFailAudit) Close() error                { return nil }

func makeCfg(mode string) *policy.Config {
	return &policy.Config{
		Mode:    mode,
		Default: policy.AllowAsk,
		Servers: map[string]policy.ServerConfig{
			"fs": {
				Command: []string{"echo"},
				Tools: map[string]policy.TargetRule{
					"read_file": {Allow: policy.AllowTrue},
					"bad_tool":  {Allow: policy.AllowFalse},
				},
			},
		},
	}
}

// assertJSONRPCError unmarshals data and asserts the JSON-RPC error code equals wantCode.
func assertJSONRPCError(t *testing.T, data []byte, wantCode int) {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, data)
	}
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error field in response: %s", data)
	}
	code, _ := errObj["code"].(float64)
	if int(code) != wantCode {
		t.Errorf("error code = %v, want %d", code, wantCode)
	}
}

func TestAllowedCallForwarded(t *testing.T) {
	agentMsg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}` + "\n"
	serverResp := `{"jsonrpc":"2.0","id":1,"result":{"content":"hello"}}` + "\n"

	var agentOut bytes.Buffer
	agentIn := transport.NewStdio(strings.NewReader(agentMsg), &agentOut)
	serverIn := transport.NewStdio(strings.NewReader(serverResp), &bytes.Buffer{})

	fa := &fakeAudit{}
	coord := approval.New()
	cfg := makeCfg("enforce")

	p := proxy.New(proxy.Config{
		AgentTransport:  agentIn,
		ServerTransport: serverIn,
		PolicyConfig:    cfg,
		Coordinator:     coord,
		AuditStore:      fa,
		ServerName:      "fs",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Run(ctx)

	if len(fa.entries) == 0 {
		t.Fatal("no audit entries recorded")
	}
	if fa.entries[0].Verdict != "ALLOW" {
		t.Errorf("verdict = %q, want ALLOW", fa.entries[0].Verdict)
	}
	if !bytes.Contains(agentOut.Bytes(), []byte("hello")) {
		t.Errorf("agent output missing server response content; got: %s", agentOut.Bytes())
	}
}

func TestDeniedCallNotForwarded(t *testing.T) {
	agentMsg := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bad_tool","arguments":{}}}` + "\n"

	var agentOut bytes.Buffer
	agentIn := transport.NewStdio(strings.NewReader(agentMsg), &agentOut)
	serverIn := transport.NewStdio(strings.NewReader(""), &bytes.Buffer{})

	fa := &fakeAudit{}
	coord := approval.New()

	p := proxy.New(proxy.Config{
		AgentTransport:  agentIn,
		ServerTransport: serverIn,
		PolicyConfig:    makeCfg("enforce"),
		Coordinator:     coord,
		AuditStore:      fa,
		ServerName:      "fs",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Run(ctx)

	if len(fa.entries) == 0 {
		t.Fatal("no audit entries")
	}
	if fa.entries[0].Verdict != "DENY" {
		t.Errorf("verdict = %q, want DENY", fa.entries[0].Verdict)
	}
	// The agent output must contain a JSON-RPC error with code -32001, not the server's response.
	assertJSONRPCError(t, agentOut.Bytes(), -32001)
}

func TestAuditWriteFailureDenies(t *testing.T) {
	agentMsg := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{}}}` + "\n"

	var agentOut bytes.Buffer
	agentIn := transport.NewStdio(strings.NewReader(agentMsg), &agentOut)
	serverIn := transport.NewStdio(strings.NewReader(""), &bytes.Buffer{})

	coord := approval.New()

	p := proxy.New(proxy.Config{
		AgentTransport:  agentIn,
		ServerTransport: serverIn,
		PolicyConfig:    makeCfg("enforce"),
		Coordinator:     coord,
		AuditStore:      &fakeFailAudit{},
		ServerName:      "fs",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Run(ctx)

	assertJSONRPCError(t, agentOut.Bytes(), -32001)
}

func TestNonGatedPassthrough(t *testing.T) {
	// "initialize" is not a gated method (not tools/call or resources/read).
	agentMsg := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	serverResp := `{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}` + "\n"

	var agentOut bytes.Buffer
	agentIn := transport.NewStdio(strings.NewReader(agentMsg), &agentOut)
	serverIn := transport.NewStdio(strings.NewReader(serverResp), &bytes.Buffer{})

	fa := &fakeAudit{}
	coord := approval.New()

	p := proxy.New(proxy.Config{
		AgentTransport:  agentIn,
		ServerTransport: serverIn,
		PolicyConfig:    makeCfg("enforce"),
		Coordinator:     coord,
		AuditStore:      fa,
		ServerName:      "fs",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Run(ctx)

	if !bytes.Contains(agentOut.Bytes(), []byte("capabilities")) {
		t.Errorf("agent output missing server response; got: %s", agentOut.Bytes())
	}
	if len(fa.entries) != 0 {
		t.Errorf("expected no audit entries for non-gated call, got %d", len(fa.entries))
	}
}

func TestAskCollapsedToDeny(t *testing.T) {
	// "unknown_tool" is not in config; Default is AllowAsk → VerdictUnknown.
	// In enforce mode this must collapse to DENY (via timeout since no resolver).
	agentMsg := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}` + "\n"

	var agentOut bytes.Buffer
	agentIn := transport.NewStdio(strings.NewReader(agentMsg), &agentOut)
	serverIn := transport.NewStdio(strings.NewReader(""), &bytes.Buffer{})

	fa := &fakeAudit{}
	coord := approval.New()

	p := proxy.New(proxy.Config{
		AgentTransport:  agentIn,
		ServerTransport: serverIn,
		PolicyConfig:    makeCfg("enforce"),
		Coordinator:     coord,
		AuditStore:      fa,
		ServerName:      "fs",
		ApprovalTimeout: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Run(ctx)

	if len(fa.entries) == 0 {
		t.Fatal("no audit entries recorded")
	}
	if fa.entries[0].Verdict != "DENY" {
		t.Errorf("verdict = %q, want DENY (ask should collapse in enforce mode)", fa.entries[0].Verdict)
	}
	assertJSONRPCError(t, agentOut.Bytes(), -32001)
}

func TestAskParksAndResolvesAllow(t *testing.T) {
	agentMsg := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"pending_tool","arguments":{}}}` + "\n"
	serverResp := `{"jsonrpc":"2.0","id":7,"result":{"ok":true}}` + "\n"

	var agentOut bytes.Buffer
	agentIn := transport.NewStdio(strings.NewReader(agentMsg), &agentOut)
	serverIn := transport.NewStdio(strings.NewReader(serverResp), &bytes.Buffer{})

	fa := &fakeAudit{}
	coord := approval.New()

	cfg := &policy.Config{
		Mode:    "enforce",
		Default: policy.AllowAsk,
		Servers: map[string]policy.ServerConfig{},
	}

	p := proxy.New(proxy.Config{
		AgentTransport:  agentIn,
		ServerTransport: serverIn,
		PolicyConfig:    cfg,
		Coordinator:     coord,
		AuditStore:      fa,
		ServerName:      "fs",
		ApprovalTimeout: 2 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx)
	}()

	time.Sleep(30 * time.Millisecond)
	coord.Resolve("fs:7", approval.VerdictAllow)

	<-done

	if len(fa.entries) == 0 {
		t.Fatal("no audit entry")
	}
	if fa.entries[0].Verdict != "ALLOW" {
		t.Errorf("verdict = %q, want ALLOW", fa.entries[0].Verdict)
	}
	if !bytes.Contains(agentOut.Bytes(), []byte("true")) {
		t.Error("agent did not receive server response after approval")
	}
}

func TestAskTimeoutDenies(t *testing.T) {
	agentMsg := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"pending_tool","arguments":{}}}` + "\n"

	var agentOut bytes.Buffer
	agentIn := transport.NewStdio(strings.NewReader(agentMsg), &agentOut)
	serverIn := transport.NewStdio(strings.NewReader(""), &bytes.Buffer{})

	fa := &fakeAudit{}
	coord := approval.New()

	cfg := &policy.Config{
		Mode:    "enforce",
		Default: policy.AllowAsk,
		Servers: map[string]policy.ServerConfig{},
	}

	p := proxy.New(proxy.Config{
		AgentTransport:  agentIn,
		ServerTransport: serverIn,
		PolicyConfig:    cfg,
		Coordinator:     coord,
		AuditStore:      fa,
		ServerName:      "fs",
		ApprovalTimeout: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Run(ctx)

	if len(fa.entries) == 0 {
		t.Fatal("no audit entry")
	}
	if fa.entries[0].Verdict != "DENY" {
		t.Errorf("verdict = %q, want DENY", fa.entries[0].Verdict)
	}
	if !bytes.Contains(agentOut.Bytes(), []byte("error")) {
		t.Error("expected JSON-RPC error after timeout")
	}
}
