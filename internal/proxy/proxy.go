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
	PolicySource    PolicySource
	Coordinator     *approval.Coordinator
	AuditStore      audit.AuditStore
	ServerName      string
	// Notifier receives lifecycle events for the web UI. Nil = disabled.
	Notifier event.Notifier
	// ApprovalTimeout is how long to wait for human approval before auto-deny.
	// Defaults to 30s if zero.
	ApprovalTimeout time.Duration
	// ServerTimeout is how long to wait for a server response before failing closed.
	// Defaults to no additional timeout when zero.
	ServerTimeout time.Duration
}

// Proxy is the core engine: reads from the agent, enforces policy, and
// forwards allowed calls to the MCP server.
// Run must be called from a single goroutine.
type Proxy struct {
	cfg Config
}

// PolicySource provides the latest policy config. Implementations may reload
// from disk, but must return the last valid config on reload errors.
type PolicySource interface {
	Get() *policy.Config
}

type staticPolicySource struct {
	cfg *policy.Config
}

func (s staticPolicySource) Get() *policy.Config { return s.cfg }

func New(cfg Config) *Proxy {
	if cfg.PolicySource == nil {
		cfg.PolicySource = staticPolicySource{cfg: cfg.PolicyConfig}
	}
	return &Proxy{cfg: cfg}
}

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
				p.sendError(ctx, msg, "server response unavailable")
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
	rawArgs := extractRawArgs(msg)
	args := displayArgs(rawArgs)
	cfg := p.policyConfig()

	verdict := policy.EvaluateArgs(p.cfg.ServerName, msg.Method, name, rawArgs, cfg)
	reason := "policy"
	approvalSource := "policy"

	// For ask/unknown in enforce mode: park for human approval.
	if (verdict == policy.VerdictAsk || verdict == policy.VerdictUnknown) &&
		cfg.Mode == "enforce" {

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
			approvalSource = "timeout"
			verdict = policy.VerdictDeny
		} else if v == approval.VerdictAllow {
			reason = "human:allow"
			approvalSource = "human"
			verdict = policy.VerdictAllow
		} else {
			reason = "human:deny"
			approvalSource = "human"
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
			approvalSource = "heuristic"
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
		Method:         msg.Method,
		Server:         p.cfg.ServerName,
		Name:           name,
		Args:           string(argsJSON),
		Verdict:        verdictStr(verdict),
		Reason:         reason,
		ApprovalSource: approvalSource,
		Warnings:       warnings,
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
			p.sendError(ctx, msg, "server response unavailable")
			return
		}
		resp, err := p.recvServerResponse(ctx)
		if err != nil {
			p.sendError(ctx, msg, "server response unavailable")
			return
		}
		if p.heuristicsEnabled() {
			if w := threatsToWarnings(scanner.Scan(string(resp.Result) + string(resp.Error))); len(w) > 0 {
				inVerdict := policy.VerdictAllow
				inReason := "heuristic:inbound"
				if p.blockOnWarn() {
					inVerdict = policy.VerdictDeny
					inReason = "heuristic:inbound:block_on_warn"
				}
				inEntry := audit.Entry{
					Method:         msg.Method,
					Server:         p.cfg.ServerName,
					Name:           name,
					Args:           "",
					Verdict:        verdictStr(inVerdict),
					Reason:         inReason,
					ApprovalSource: "heuristic",
					Warnings:       w,
				}
				if err := p.cfg.AuditStore.Append(inEntry); err != nil {
					slog.Error("inbound audit write failed — withholding result", "err", err)
					p.sendError(ctx, msg, "audit unavailable — result withheld")
					return
				}
				if p.cfg.Notifier != nil {
					p.cfg.Notifier.Broadcast("audit", inEntry)
				}
				if inVerdict == policy.VerdictDeny {
					p.sendError(ctx, msg, "result withheld: heuristic match")
					return
				}
			}
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
	if p.cfg.ServerTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.cfg.ServerTimeout)
		defer cancel()
	}
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
	cfg := p.policyConfig()
	verdict := policy.EvaluateArgs(p.cfg.ServerName, msg.Method, "", nil, cfg)
	reason := "policy"
	approvalSource := "policy"

	var warnings []audit.Warning
	if p.heuristicsEnabled() {
		warnings = threatsToWarnings(scanner.Scan(string(msg.Params)))
		if len(warnings) > 0 && p.blockOnWarn() && verdict == policy.VerdictAllow {
			verdict = policy.VerdictDeny
			reason = "heuristic:block_on_warn"
			approvalSource = "heuristic"
		}
	}

	slog.Info("verdict",
		"server", p.cfg.ServerName,
		"method", msg.Method,
		"direction", "server->agent",
		"verdict", verdict,
		"reason", reason,
	)

	entry := audit.Entry{
		Method:         msg.Method,
		Server:         p.cfg.ServerName,
		Name:           "",
		Args:           "",
		Verdict:        verdictStr(verdict),
		Reason:         reason,
		ApprovalSource: approvalSource,
		Warnings:       warnings,
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

func (p *Proxy) policyConfig() *policy.Config {
	cfg := p.cfg.PolicySource.Get()
	if cfg == nil {
		return p.cfg.PolicyConfig
	}
	return cfg
}

func extractName(msg jsonrpc.Message) string {
	var params struct {
		Name string `json:"name"`
	}
	json.Unmarshal(msg.Params, &params) //nolint:errcheck
	return params.Name
}

func extractRawArgs(msg jsonrpc.Message) policy.Args {
	var params struct {
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	json.Unmarshal(msg.Params, &params) //nolint:errcheck
	return policy.Args(params.Arguments)
}

func displayArgs(args policy.Args) map[string]string {
	result := make(map[string]string, len(args))
	for k, raw := range args {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			result[k] = s
			continue
		}
		result[k] = string(raw)
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
	h := p.policyConfig().Heuristics
	return h != nil && h.Enabled
}

func (p *Proxy) blockOnWarn() bool {
	h := p.policyConfig().Heuristics
	return h != nil && h.BlockOnWarn
}
