package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/maksym-mishchenko/mcpgate/internal/approval"
	"github.com/maksym-mishchenko/mcpgate/internal/audit"
	"github.com/maksym-mishchenko/mcpgate/internal/codec"
	"github.com/maksym-mishchenko/mcpgate/internal/event"
	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
	"github.com/maksym-mishchenko/mcpgate/internal/policy"
	"github.com/maksym-mishchenko/mcpgate/internal/transport"
)

// Config holds all dependencies for a Proxy instance.
// All fields except Notifier and ApprovalTimeout are required.
type Config struct {
	AgentTransport  transport.Transport
	ServerTransport transport.Transport
	PolicyConfig    *policy.Config
	Coordinator     *approval.Coordinator
	AuditStore      audit.AuditStore
	ServerName      string
	// Notifier receives lifecycle events for the web UI. Nil = disabled.
	Notifier event.Notifier
	// ApprovalTimeout is how long to wait for human approval before auto-deny.
	// Defaults to 30s if zero.
	ApprovalTimeout time.Duration
}

// Proxy is the core engine: reads from the agent, enforces policy, and
// forwards allowed calls to the MCP server.
// Run must be called from a single goroutine.
type Proxy struct {
	cfg Config
}

func New(cfg Config) *Proxy { return &Proxy{cfg: cfg} }

// Run reads from AgentTransport until ctx is cancelled or transport error.
func (p *Proxy) Run(ctx context.Context) {
	for {
		msg, err := p.cfg.AgentTransport.Recv(ctx)
		if err != nil {
			return
		}
		if !codec.IsGated(msg) {
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
	reason := "policy"

	// For ask/unknown in enforce mode: park for human approval.
	if (verdict == policy.VerdictAsk || verdict == policy.VerdictUnknown) &&
		p.cfg.PolicyConfig.Mode == "enforce" {

		key := fmt.Sprintf("%s:%s", p.cfg.ServerName, string(msg.ID))
		call := event.PendingCall{
			Key:    key,
			Server: p.cfg.ServerName,
			Method: msg.Method,
			Name:   name,
			Args:   args,
			Ts:     time.Now(),
		}
		if p.cfg.Notifier != nil {
			p.cfg.Notifier.AddPending(key, call)
			p.cfg.Notifier.Broadcast("pending", call)
		}

		timeout := p.cfg.ApprovalTimeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		tCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		v, err := p.cfg.Coordinator.Park(tCtx, key)

		if p.cfg.Notifier != nil {
			p.cfg.Notifier.RemovePending(key)
			src := "human"
			if err != nil {
				src = "timeout"
			}
			p.cfg.Notifier.Broadcast("resolved", event.Resolved{Key: key, Verdict: v.String(), Source: src})
		}

		if err != nil {
			reason = "timeout"
			verdict = policy.VerdictDeny
		} else if v == approval.VerdictAllow {
			reason = "human:allow"
			verdict = policy.VerdictAllow
		} else {
			reason = "human:deny"
			verdict = policy.VerdictDeny
		}
	}

	slog.Info("verdict",
		"server", p.cfg.ServerName,
		"method", msg.Method,
		"name", name,
		"verdict", verdict,
		"reason", reason,
	)

	argsJSON, _ := json.Marshal(args)
	entry := audit.Entry{
		Method:  msg.Method,
		Server:  p.cfg.ServerName,
		Name:    name,
		Args:    string(argsJSON),
		Verdict: verdictStr(verdict),
		Reason:  reason,
	}
	if err := p.cfg.AuditStore.Append(entry); err != nil {
		slog.Error("audit write failed — denying call", "err", err)
		p.sendError(ctx, msg, "audit unavailable — call denied")
		return
	}

	if p.cfg.Notifier != nil {
		p.cfg.Notifier.Broadcast("audit", entry)
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
