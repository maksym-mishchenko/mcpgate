package event_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/maksym-mishchenko/mcpgate/internal/event"
)

func TestPendingCallMarshal(t *testing.T) {
	c := event.PendingCall{
		Key:    "fs:1",
		Server: "fs",
		Method: "tools/call",
		Name:   "read_file",
		Args:   map[string]string{"path": "/tmp/foo"},
		Ts:     time.Unix(1000, 0).UTC(),
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got event.PendingCall
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Key != c.Key || got.Name != c.Name {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestResolvedMarshal(t *testing.T) {
	r := event.Resolved{Key: "fs:1", Verdict: "ALLOW", Source: "human"}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got event.Resolved
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Source != "human" {
		t.Errorf("source = %q, want human", got.Source)
	}
}
