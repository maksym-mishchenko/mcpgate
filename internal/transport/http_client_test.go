package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
	"github.com/maksym-mishchenko/mcpgate/internal/transport"
)

func TestHTTPTransportRoundtrip(t *testing.T) {
	// Mock MCP server that echoes back with a result.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonrpc.Message
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		result, _ := json.Marshal(map[string]string{"status": "ok"})
		resp := jsonrpc.Message{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer srv.Close()

	tr := transport.NewHTTP(srv.URL)
	defer tr.Close()

	id, _ := json.Marshal(42)
	msg := jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"test"}`),
	}

	ctx := context.Background()
	if err := tr.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	resp, err := tr.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}

	if string(resp.ID) != "42" {
		t.Errorf("response ID = %s, want 42", resp.ID)
	}
	if resp.Result == nil {
		t.Error("expected result, got nil")
	}
}

func TestHTTPTransportServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	tr := transport.NewHTTP(srv.URL)
	defer tr.Close()

	ctx := context.Background()
	id, _ := json.Marshal(1)
	if err := tr.Send(ctx, jsonrpc.Message{JSONRPC: "2.0", ID: id, Method: "tools/call"}); err == nil {
		t.Error("expected error on 500 response")
	}
}

func TestHTTPTransportContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until client cancels.
		<-r.Context().Done()
	}))
	defer srv.Close()

	tr := transport.NewHTTP(srv.URL)
	defer tr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	id, _ := json.Marshal(1)
	go func() {
		cancel()
	}()
	err := tr.Send(ctx, jsonrpc.Message{JSONRPC: "2.0", ID: id, Method: "tools/call"})
	if err == nil {
		t.Error("expected error on context cancel")
	}
}
