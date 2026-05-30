package child_test

import (
	"context"
	"testing"
	"time"

	"github.com/maksym-mishchenko/mcpgate/internal/child"
	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
)

func TestStartStop(t *testing.T) {
	m, err := child.Start(context.Background(), []string{"cat"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestSendReceive(t *testing.T) {
	m, err := child.Start(context.Background(), []string{"cat"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	msg := jsonrpc.Message{JSONRPC: "2.0", Method: "ping"}
	if err := m.Transport().Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := m.Transport().Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if resp.Method != "ping" {
		t.Errorf("method = %q, want ping", resp.Method)
	}
}

func TestExitNotifiesChan(t *testing.T) {
	m, err := child.Start(context.Background(), []string{"true"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-m.Done():
	case <-time.After(2 * time.Second):
		t.Error("process did not exit within 2s")
	}
}
