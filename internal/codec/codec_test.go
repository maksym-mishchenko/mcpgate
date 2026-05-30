package codec_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/codec"
	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
)

func TestReadSingleMessage(t *testing.T) {
	r := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}` + "\n")
	c := codec.New(r)
	msg, err := c.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if msg.Method != "tools/call" {
		t.Errorf("method = %q, want tools/call", msg.Method)
	}
}

func TestReadClassifiesGatedMethods(t *testing.T) {
	cases := []struct {
		line  string
		gated bool
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`, true},
		{`{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{}}`, true},
		{`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/message","params":{}}`, false},
	}
	for _, c := range cases {
		r := strings.NewReader(c.line + "\n")
		cd := codec.New(r)
		msg, err := cd.Read()
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if got := codec.IsGated(msg); got != c.gated {
			t.Errorf("IsGated(%q) = %v, want %v", msg.Method, got, c.gated)
		}
	}
}

func TestReadBatchSplits(t *testing.T) {
	// A JSON-RPC batch array must be split into individual messages.
	line := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}},{"jsonrpc":"2.0","method":"notifications/x","params":{}}]` + "\n"
	r := strings.NewReader(line)
	c := codec.New(r)
	msg1, err := c.Read()
	if err != nil {
		t.Fatalf("Read msg1: %v", err)
	}
	if msg1.Method != "tools/call" {
		t.Errorf("msg1.Method = %q", msg1.Method)
	}
	msg2, err := c.Read()
	if err != nil {
		t.Fatalf("Read msg2: %v", err)
	}
	if msg2.Method != "notifications/x" {
		t.Errorf("msg2.Method = %q", msg2.Method)
	}
}

func TestReadLargeMessage(t *testing.T) {
	// Ensure lines > 64KB don't truncate (regression for bufio.Scanner 64KB cap).
	big := strings.Repeat("x", 128*1024)
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"data":"` + big + `"}}` + "\n"
	r := strings.NewReader(line)
	c := codec.New(r)
	msg, err := c.Read()
	if err != nil {
		t.Fatalf("Read large: %v", err)
	}
	if msg.Method != "tools/call" {
		t.Errorf("method = %q", msg.Method)
	}
}

func TestReadEOF(t *testing.T) {
	c := codec.New(strings.NewReader(""))
	_, err := c.Read()
	if err != io.EOF {
		t.Errorf("want io.EOF, got %v", err)
	}
}

func TestWriteAppendsNewline(t *testing.T) {
	var buf bytes.Buffer
	c := codec.NewWriter(&buf)
	msg := jsonrpc.Message{JSONRPC: "2.0", Method: "tools/call"}
	if err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if out[len(out)-1] != '\n' {
		t.Error("Write did not append newline")
	}
}

func TestReadMalformedJSON(t *testing.T) {
	c := codec.New(strings.NewReader("not-json\n"))
	_, err := c.Read()
	if err == nil {
		t.Error("want error for malformed JSON, got nil")
	}
}

func TestReadMalformedBatch(t *testing.T) {
	c := codec.New(strings.NewReader("[not-json]\n"))
	_, err := c.Read()
	if err == nil {
		t.Error("want error for malformed batch, got nil")
	}
}
