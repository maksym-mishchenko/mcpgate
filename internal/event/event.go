package event

import "time"

// PendingCall represents a gated call parked for human approval.
type PendingCall struct {
	Key    string            `json:"key"`
	Server string            `json:"server"`
	Method string            `json:"method"`
	Name   string            `json:"name"`
	Args   map[string]string `json:"args"`
	Ts     time.Time         `json:"ts"`
}

// Resolved is broadcast when a pending call is approved, denied, or timed out.
type Resolved struct {
	Key     string `json:"key"`
	Verdict string `json:"verdict"`
	Source  string `json:"source"` // "human" | "timeout"
}

// Notifier receives call lifecycle events from the proxy engine.
// web.Server implements this interface; a nil Notifier is valid (no-op).
type Notifier interface {
	Broadcast(event string, data any)
	AddPending(key string, c PendingCall)
	RemovePending(key string)
}
