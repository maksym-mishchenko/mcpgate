package audit

import "time"

// Entry is a single audit log record.
type Entry struct {
	ID      int64
	Seq     int64
	Method  string
	Server  string
	Name    string
	Args    string // JSON
	Verdict string
	Reason  string
	Ts      time.Time
	Hash    string
	Status  string // "PENDING" | "DONE"
}

// AuditStore is the interface for appending and verifying audit entries.
// Tests inject a failing store to prove fail-closed behaviour.
type AuditStore interface {
	Append(e Entry) error
	VerifyChain() (ok bool, err error)
	Close() error
}
