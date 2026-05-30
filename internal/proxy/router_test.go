package proxy_test

import (
	"context"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
	"github.com/maksym-mishchenko/mcpgate/internal/proxy"
)

// stubTransport is a minimal Transport for tests
type stubTransport struct {
	sendFunc func(context.Context, jsonrpc.Message) error
	recvFunc func(context.Context) (jsonrpc.Message, error)
}

func (s *stubTransport) Send(ctx context.Context, m jsonrpc.Message) error {
	if s.sendFunc != nil {
		return s.sendFunc(ctx, m)
	}
	return nil
}
func (s *stubTransport) Recv(ctx context.Context) (jsonrpc.Message, error) {
	if s.recvFunc != nil {
		return s.recvFunc(ctx)
	}
	return jsonrpc.Message{}, nil
}
func (s *stubTransport) Close() error { return nil }

func TestRouterGetExists(t *testing.T) {
	r := proxy.NewRouter()
	stub := &stubTransport{}
	r.Add("fs", stub)

	got, ok := r.Get("fs")
	if !ok {
		t.Fatal("expected to find 'fs'")
	}
	if got != stub {
		t.Fatal("expected same transport")
	}
}

func TestRouterGetMissing(t *testing.T) {
	r := proxy.NewRouter()
	_, ok := r.Get("missing")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestRouterNames(t *testing.T) {
	r := proxy.NewRouter()
	r.Add("a", &stubTransport{})
	r.Add("b", &stubTransport{})

	names := r.Names()
	if len(names) != 2 {
		t.Errorf("expected 2 names, got %d", len(names))
	}
}
