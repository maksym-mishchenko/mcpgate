package jsonrpc_test

import (
	"encoding/json"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
)

func TestMessageKind(t *testing.T) {
	cases := []struct {
		raw  string
		want jsonrpc.Kind
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`, jsonrpc.KindRequest},
		{`{"jsonrpc":"2.0","id":1,"result":{}}`, jsonrpc.KindResponse},
		{`{"jsonrpc":"2.0","method":"notifications/message","params":{}}`, jsonrpc.KindNotification},
		{`{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{}}`, jsonrpc.KindRequest},
	}
	for _, c := range cases {
		var m jsonrpc.Message
		if err := json.Unmarshal([]byte(c.raw), &m); err != nil {
			t.Fatalf("unmarshal %s: %v", c.raw, err)
		}
		if got := m.Kind(); got != c.want {
			t.Errorf("Kind(%s) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestIDString(t *testing.T) {
	cases := []struct{ raw, want string }{
		{`{"jsonrpc":"2.0","id":42,"method":"m","params":{}}`, "42"},
		{`{"jsonrpc":"2.0","id":"abc","method":"m","params":{}}`, "abc"},
	}
	for _, c := range cases {
		var m jsonrpc.Message
		json.Unmarshal([]byte(c.raw), &m)
		if got := m.IDString(); got != c.want {
			t.Errorf("IDString = %q, want %q", got, c.want)
		}
	}
}
