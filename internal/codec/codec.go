package codec

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
)

var gatedMethods = map[string]bool{
	"tools/call":     true,
	"resources/read": true,
	"prompts/get":    true,
}

// IsGated reports whether a message's method requires policy enforcement.
func IsGated(m jsonrpc.Message) bool {
	return gatedMethods[m.Method]
}

// Reader reads newline-delimited JSON-RPC messages from r.
// It handles batch arrays by splitting them into individual messages.
type Reader struct {
	br      *bufio.Reader
	pending []jsonrpc.Message // leftover messages from a batch
}

// New returns a Reader backed by r. Uses a 256 KB buffer to handle lines
// larger than bufio.Scanner's 64 KB default limit.
func New(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, 256*1024)}
}

// Read returns the next JSON-RPC message. Returns io.EOF when r is exhausted.
// Malformed JSON returns an error (fail-closed).
func (c *Reader) Read() (jsonrpc.Message, error) {
	if len(c.pending) > 0 {
		msg := c.pending[0]
		c.pending = c.pending[1:]
		return msg, nil
	}

	line, err := c.br.ReadString('\n')
	if err != nil && len(line) == 0 {
		return jsonrpc.Message{}, err
	}

	trimmed := bytes.TrimRight([]byte(line), "\r\n")
	if len(trimmed) == 0 {
		return c.Read() // skip blank lines
	}

	// Detect batch array.
	if trimmed[0] == '[' {
		var msgs []jsonrpc.Message
		if jsonErr := json.Unmarshal(trimmed, &msgs); jsonErr != nil {
			return jsonrpc.Message{}, fmt.Errorf("codec: unmarshal batch: %w", jsonErr)
		}
		if len(msgs) == 0 {
			return c.Read()
		}
		for i := range msgs {
			msgs[i].Raw = trimmed
		}
		c.pending = msgs[1:]
		return msgs[0], nil
	}

	var msg jsonrpc.Message
	if jsonErr := json.Unmarshal(trimmed, &msg); jsonErr != nil {
		return jsonrpc.Message{}, fmt.Errorf("codec: unmarshal: %w", jsonErr)
	}
	msg.Raw = append([]byte(nil), trimmed...)
	return msg, nil
}

// Writer writes newline-delimited JSON-RPC messages to w.
type Writer struct {
	w io.Writer
}

// NewWriter returns a Writer that serialises messages to w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write serialises msg as JSON and appends a newline.
func (c *Writer) Write(msg jsonrpc.Message) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = c.w.Write(b)
	return err
}
