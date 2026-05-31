package audit

import "time"

// Warning is a heuristic match recorded against an audit entry. It mirrors
// scanner.Threat but lives here so the audit package has no scanner dependency.
type Warning struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Snippet  string `json:"snippet"`
}

// Entry is a single audit log record.
type Entry struct {
	ID       int64
	Seq      int64
	Method   string
	Server   string
	Name     string
	Args     string // JSON
	Verdict  string
	Reason   string
	Ts       time.Time
	Hash     string
	Status   string    // "PENDING" | "DONE"
	Warnings []Warning // heuristic matches; empty for most rows
}

// AuditStore is the interface for appending and verifying audit entries.
// Tests inject a failing store to prove fail-closed behaviour.
type AuditStore interface {
	Append(e Entry) error
	VerifyChain() (ok bool, err error)
	Close() error
}

// AuditQuerier extends the store with read access for the web UI.
// sqliteStore implements this; tests may or may not.
type AuditQuerier interface {
	Recent(n int) ([]Entry, error)
}
