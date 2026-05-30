package jsonrpc

import (
	"encoding/json"
	"fmt"
)

type Kind int

const (
	KindUnknown      Kind = iota
	KindRequest           // has method + id
	KindResponse          // has result or error, no method
	KindNotification      // has method, no id
)

// Message is a raw JSON-RPC 2.0 frame.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
	Raw     []byte          `json:"-"` // original bytes
}

func (m *Message) Kind() Kind {
	hasMethod := m.Method != ""
	hasID := len(m.ID) > 0
	switch {
	case hasMethod && hasID:
		return KindRequest
	case hasMethod && !hasID:
		return KindNotification
	case !hasMethod && (len(m.Result) > 0 || len(m.Error) > 0):
		return KindResponse
	default:
		return KindUnknown
	}
}

// IDString returns a stable string key for the message ID (int or string).
func (m *Message) IDString() string {
	if len(m.ID) == 0 {
		return ""
	}
	// strip quotes if it's a JSON string
	var s string
	if err := json.Unmarshal(m.ID, &s); err == nil {
		return s
	}
	return fmt.Sprintf("%s", m.ID)
}
