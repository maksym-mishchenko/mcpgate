package transport_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
	"github.com/maksym-mishchenko/mcpgate/internal/transport"
)

func TestStdioTransportRecvSend(t *testing.T) {
	incoming := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}` + "\n")
	var outgoing bytes.Buffer

	tr := transport.NewStdio(incoming, &outgoing)
	ctx := context.Background()

	msg, err := tr.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if msg.Method != "tools/call" {
		t.Errorf("method = %q", msg.Method)
	}

	resp := jsonrpc.Message{JSONRPC: "2.0", ID: msg.ID, Result: []byte(`{}`)}
	if err := tr.Send(ctx, resp); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !bytes.Contains(outgoing.Bytes(), []byte("result")) {
		t.Error("outgoing buffer missing result")
	}
}

func TestStdioTransportEOF(t *testing.T) {
	tr := transport.NewStdio(strings.NewReader(""), io.Discard)
	_, err := tr.Recv(context.Background())
	if err != io.EOF {
		t.Errorf("want io.EOF, got %v", err)
	}
}

func TestStdioTransportClose(t *testing.T) {
	tr := transport.NewStdio(strings.NewReader(""), io.Discard)
	if err := tr.Close(); err != nil {
		t.Error(err)
	}
}
