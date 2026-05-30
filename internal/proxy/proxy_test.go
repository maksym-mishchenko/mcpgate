package proxy_test

import (
	"bytes"
	"context"
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
	// The agent output must contain a JSON-RPC error, not the server's response.
	if !bytes.Contains(agentOut.Bytes(), []byte("error")) {
		t.Error("agent output missing JSON-RPC error for denied call")
	}
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

	if !bytes.Contains(agentOut.Bytes(), []byte("error")) {
		t.Error("audit failure did not produce a JSON-RPC error (not fail-closed)")
	}
}
