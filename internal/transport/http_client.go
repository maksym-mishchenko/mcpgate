package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
)

// HTTPTransport implements Transport by POST-ing JSON-RPC to an HTTP endpoint.
// It is designed for sequential use: Send followed by Recv.
// Thread-safe but not designed for concurrent Send/Recv pairs.
type HTTPTransport struct {
	endpoint   string
	httpClient *http.Client

	mu      sync.Mutex
	pending *bytes.Buffer // response body from last Send
}

// NewHTTP creates an HTTPTransport pointing at endpoint.
// endpoint is a full URL, e.g. "http://localhost:8080/mcp".
func NewHTTP(endpoint string) *HTTPTransport {
	return &HTTPTransport{
		endpoint:   endpoint,
		httpClient: &http.Client{},
	}
}

// NewHTTPWithClient creates an HTTPTransport with a custom http.Client.
// Use this for egress allowlist enforcement.
func NewHTTPWithClient(endpoint string, client *http.Client) *HTTPTransport {
	return &HTTPTransport{
		endpoint:   endpoint,
		httpClient: client,
	}
}

// Send POST-s the message to the endpoint and stores the response for Recv.
func (t *HTTPTransport) Send(ctx context.Context, m jsonrpc.Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("http transport: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("http transport: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http transport: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		return fmt.Errorf("http transport: server returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("http transport: read body: %w", err)
	}

	t.mu.Lock()
	t.pending = bytes.NewBuffer(data)
	t.mu.Unlock()
	return nil
}

// Recv decodes the response buffered by the previous Send.
// It returns an error if Send has not been called first.
func (t *HTTPTransport) Recv(_ context.Context) (jsonrpc.Message, error) {
	t.mu.Lock()
	buf := t.pending
	t.pending = nil
	t.mu.Unlock()

	if buf == nil {
		return jsonrpc.Message{}, fmt.Errorf("http transport: Recv called with no pending response")
	}

	var msg jsonrpc.Message
	if err := json.NewDecoder(buf).Decode(&msg); err != nil {
		return jsonrpc.Message{}, fmt.Errorf("http transport: decode response: %w", err)
	}
	return msg, nil
}

// Close is a no-op for HTTP transport (connections are per-request).
func (t *HTTPTransport) Close() error { return nil }
