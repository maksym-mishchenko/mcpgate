package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/maksym-mishchenko/mcpgate/internal/approval"
	"github.com/maksym-mishchenko/mcpgate/internal/audit"
	"github.com/maksym-mishchenko/mcpgate/internal/codec"
	"github.com/maksym-mishchenko/mcpgate/internal/event"
	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
	"github.com/maksym-mishchenko/mcpgate/internal/policy"
	"github.com/maksym-mishchenko/mcpgate/internal/scanner"
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
			resp, err := p.recvServerResponse(ctx)
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

	var warnings []audit.Warning
	if p.heuristicsEnabled() {
		var sb strings.Builder
		sb.WriteString(name)
		for k, v := range args {
			sb.WriteByte(' ')
			sb.WriteString(k)
			sb.WriteByte('=')
			sb.WriteString(v)
		}
		warnings = threatsToWarnings(scanner.Scan(sb.String()))
		if len(warnings) > 0 && p.blockOnWarn() && verdict == policy.VerdictAllow {
			verdict = policy.VerdictDeny
			reason = "heuristic:block_on_warn"
		}
	}

	slog.Info("verdict",
		"server", p.cfg.ServerName,
		"method", msg.Method,
		"name", name,
		"verdict", verdict,
		"reason", reason,
		"warnings", len(warnings),
	)

	argsJSON, _ := json.Marshal(args)
	entry := audit.Entry{
		Method:   msg.Method,
		Server:   p.cfg.ServerName,
		Name:     name,
		Args:     string(argsJSON),
		Verdict:  verdictStr(verdict),
		Reason:   reason,
		Warnings: warnings,
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
		resp, err := p.recvServerResponse(ctx)
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

// recvServerResponse reads from the server, transparently handling any
// server-initiated requests (e.g. sampling/createMessage) by applying policy
// before relaying them to the agent. It also relays any notifications (e.g.
// progress updates) to the agent. It returns once the server sends an
// actual response (a frame that is neither a request nor a notification).
func (p *Proxy) recvServerResponse(ctx context.Context) (jsonrpc.Message, error) {
	for {
		msg, err := p.cfg.ServerTransport.Recv(ctx)
		if err != nil {
			return jsonrpc.Message{}, err
		}

		switch msg.Kind() {
		case jsonrpc.KindRequest:
			// Server-initiated request (e.g. sampling/createMessage) → apply policy.
			if err := p.handleServerRequest(ctx, msg); err != nil {
				return jsonrpc.Message{}, err
			}
			continue
		case jsonrpc.KindNotification:
			// Relay server notifications (e.g. progress) to the agent and keep
			// waiting for the actual response.
			if err := p.cfg.AgentTransport.Send(ctx, msg); err != nil {
				return jsonrpc.Message{}, err
			}
			continue
		default:
			return msg, nil
		}
	}
}

// handleServerRequest applies policy to a server-initiated request
// (e.g. sampling/createMessage). On ALLOW it relays to the agent and pumps the
// agent's reply back to the server. On DENY it sends a JSON-RPC error to the
// server. Every decision is audited.
func (p *Proxy) handleServerRequest(ctx context.Context, msg jsonrpc.Message) error {
	verdict := policy.Evaluate(p.cfg.ServerName, msg.Method, "", nil, p.cfg.PolicyConfig)

	slog.Info("verdict",
		"server", p.cfg.ServerName,
		"method", msg.Method,
		"direction", "server->agent",
		"verdict", verdict,
		"reason", "policy",
	)

	entry := audit.Entry{
		Method:  msg.Method,
		Server:  p.cfg.ServerName,
		Name:    "",
		Args:    "",
		Verdict: verdictStr(verdict),
		Reason:  "policy",
	}
	if err := p.cfg.AuditStore.Append(entry); err != nil {
		slog.Error("audit write failed — denying reverse call", "err", err)
		p.sendServerError(ctx, msg, "audit unavailable — call denied")
		return nil
	}
	if p.cfg.Notifier != nil {
		p.cfg.Notifier.Broadcast("audit", entry)
	}

	if verdict != policy.VerdictAllow {
		p.sendServerError(ctx, msg, "denied by policy")
		return nil
	}

	if err := p.cfg.AgentTransport.Send(ctx, msg); err != nil {
		return err
	}
	reply, err := p.cfg.AgentTransport.Recv(ctx)
	if err != nil {
		return err
	}
	return p.cfg.ServerTransport.Send(ctx, reply)
}

// sendServerError sends a JSON-RPC error response to the server, addressed to
// the server-initiated request's ID.
func (p *Proxy) sendServerError(ctx context.Context, req jsonrpc.Message, message string) {
	errObj, _ := json.Marshal(map[string]any{
		"code":    -32001,
		"message": message,
	})
	resp := jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      req.ID,
		Error:   errObj,
	}
	p.cfg.ServerTransport.Send(ctx, resp) //nolint:errcheck
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

func threatsToWarnings(ts []scanner.Threat) []audit.Warning {
	if len(ts) == 0 {
		return nil
	}
	out := make([]audit.Warning, len(ts))
	for i, t := range ts {
		out[i] = audit.Warning{ID: t.ID, Severity: t.Severity, Snippet: t.Snippet}
	}
	return out
}

func (p *Proxy) heuristicsEnabled() bool {
	h := p.cfg.PolicyConfig.Heuristics
	return h != nil && h.Enabled
}

func (p *Proxy) blockOnWarn() bool {
	h := p.cfg.PolicyConfig.Heuristics
	return h != nil && h.BlockOnWarn
}
