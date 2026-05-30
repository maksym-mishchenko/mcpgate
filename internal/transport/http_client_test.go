package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestEgressAllowlistBlocks(t *testing.T) {
	// Server on localhost — will be blocked because allowlist is empty.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Extract just the host from srv.URL (e.g. "127.0.0.1:PORT").
	u, _ := url.Parse(srv.URL)
	host := u.Hostname() // "127.0.0.1"

	// Allowlist is empty — every host blocked.
	tr := transport.NewHTTPWithEgress(srv.URL, []string{})
	defer tr.Close()

	ctx := context.Background()
	id, _ := json.Marshal(1)
	err := tr.Send(ctx, jsonrpc.Message{JSONRPC: "2.0", ID: id, Method: "tools/call"})
	if err == nil {
		t.Errorf("expected egress block, host=%s", host)
	}
	if !strings.Contains(err.Error(), "egress") {
		t.Errorf("error should mention egress, got: %v", err)
	}
}

func TestEgressAllowlistPermits(t *testing.T) {
	result, _ := json.Marshal(map[string]bool{"ok": true})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonrpc.Message
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		resp, _ := json.Marshal(jsonrpc.Message{JSONRPC: "2.0", ID: req.ID, Result: result})
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp) //nolint:errcheck
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	host := u.Hostname() // "127.0.0.1"

	// Allowlist contains the server's host.
	tr := transport.NewHTTPWithEgress(srv.URL, []string{host})
	defer tr.Close()

	ctx := context.Background()
	id, _ := json.Marshal(2)
	if err := tr.Send(ctx, jsonrpc.Message{JSONRPC: "2.0", ID: id, Method: "tools/call"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	resp, err := tr.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Result == nil {
		t.Error("expected result")
	}
}
