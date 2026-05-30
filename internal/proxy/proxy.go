package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/maksym-mishchenko/mcpgate/internal/approval"
	"github.com/maksym-mishchenko/mcpgate/internal/audit"
	"github.com/maksym-mishchenko/mcpgate/internal/codec"
	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
	"github.com/maksym-mishchenko/mcpgate/internal/policy"
	"github.com/maksym-mishchenko/mcpgate/internal/transport"
)

// Config holds all dependencies for a Proxy instance.
type Config struct {
	AgentTransport  transport.Transport
	ServerTransport transport.Transport
	PolicyConfig    *policy.Config
	Coordinator     *approval.Coordinator
	AuditStore      audit.AuditStore
	ServerName      string
}

// Proxy is the core engine: it reads from the agent, enforces policy, and
// forwards allowed calls to the MCP server.
type Proxy struct {
	cfg Config
}

func New(cfg Config) *Proxy { return &Proxy{cfg: cfg} }

// Run reads messages from the agent transport, applies policy, and forwards
// to the server transport. It returns when ctx is cancelled or either
// transport returns an error.
func (p *Proxy) Run(ctx context.Context) {
	for {
		msg, err := p.cfg.AgentTransport.Recv(ctx)
		if err != nil {
			return
		}

		if !codec.IsGated(msg) {
			// Pass non-gated traffic through untouched.
			if err := p.cfg.ServerTransport.Send(ctx, msg); err != nil {
				return
			}
			resp, err := p.cfg.ServerTransport.Recv(ctx)
			if err != nil {
				return
			}
			p.cfg.AgentTransport.Send(ctx, resp) //nolint:errcheck
			continue
		}

		p.handleGated(ctx, msg)
	}
}

func (p *Proxy) handleGated(ctx context.Context, msg jsonrpc.Message) {
	name := extractName(msg)
	args := extractArgs(msg)

	verdict := policy.Evaluate(p.cfg.ServerName, msg.Method, name, args, p.cfg.PolicyConfig)

	// UNKNOWN/ASK in enforce mode → deny (interactive approval is v0.2).
	if verdict == policy.VerdictUnknown || verdict == policy.VerdictAsk {
		if p.cfg.PolicyConfig.Mode == "enforce" {
			verdict = policy.VerdictDeny
		}
	}

	// Write-ahead audit — fail-closed: any write failure denies the call.
	entry := audit.Entry{
		Method:  msg.Method,
		Server:  p.cfg.ServerName,
		Name:    name,
		Verdict: verdictStr(verdict),
	}
	if err := p.cfg.AuditStore.Append(entry); err != nil {
		slog.Error("audit write failed — denying call", "err", err)
		p.sendError(ctx, msg, "audit unavailable — call denied")
		return
	}

	switch verdict {
	case policy.VerdictAllow:
		if err := p.cfg.ServerTransport.Send(ctx, msg); err != nil {
			return
		}
		resp, err := p.cfg.ServerTransport.Recv(ctx)
		if err != nil {
			return
		}
		p.cfg.AgentTransport.Send(ctx, resp) //nolint:errcheck

	case policy.VerdictDeny:
		p.sendError(ctx, msg, "denied by policy")

	default:
		p.sendError(ctx, msg, "call denied")
	}
}

func (p *Proxy) sendError(ctx context.Context, req jsonrpc.Message, message string) {
	errObj, _ := json.Marshal(map[string]any{
		"code":    -32001,
		"message": message,
	})
	resp := jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      req.ID,
		Error:   errObj,
	}
	p.cfg.AgentTransport.Send(ctx, resp) //nolint:errcheck
}

func extractName(msg jsonrpc.Message) string {
	var params struct {
		Name string `json:"name"`
	}
	json.Unmarshal(msg.Params, &params) //nolint:errcheck
	return params.Name
}

func extractArgs(msg jsonrpc.Message) map[string]string {
	var params struct {
		Arguments map[string]any `json:"arguments"`
	}
	json.Unmarshal(msg.Params, &params) //nolint:errcheck
	result := make(map[string]string, len(params.Arguments))
	for k, v := range params.Arguments {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}

func verdictStr(v policy.Verdict) string { return v.String() }
