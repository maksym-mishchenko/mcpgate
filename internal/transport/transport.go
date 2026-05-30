package transport

import (
	"context"

	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
)

// Transport abstracts a bidirectional JSON-RPC message channel.
// The proxy engine uses two Transport values (agent-side, server-side)
// and never touches file descriptors or processes directly.
type Transport interface {
	Recv(ctx context.Context) (jsonrpc.Message, error)
	Send(ctx context.Context, m jsonrpc.Message) error
	Close() error
}
