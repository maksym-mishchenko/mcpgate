package transport

import (
	"context"
	"io"

	"github.com/maksym-mishchenko/mcpgate/internal/codec"
	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
)

type StdioTransport struct {
	reader *codec.Reader
	writer *codec.Writer
	closer io.Closer
}

// NewStdio wraps an io.Reader (incoming) and io.Writer (outgoing) as a Transport.
// If w implements io.Closer, it is closed on Close().
func NewStdio(r io.Reader, w io.Writer) *StdioTransport {
	var c io.Closer
	if cl, ok := w.(io.Closer); ok {
		c = cl
	}
	return &StdioTransport{
		reader: codec.New(r),
		writer: codec.NewWriter(w),
		closer: c,
	}
}

func (s *StdioTransport) Recv(_ context.Context) (jsonrpc.Message, error) {
	return s.reader.Read()
}

func (s *StdioTransport) Send(_ context.Context, m jsonrpc.Message) error {
	return s.writer.Write(m)
}

func (s *StdioTransport) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}
