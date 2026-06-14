package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/maksym-mishchenko/mcpgate/internal/jsonrpc"
)

// HTTPTransport implements Transport by POST-ing JSON-RPC to an HTTP endpoint.
// It is designed for sequential use: Send followed by Recv.
// Thread-safe but not designed for concurrent Send/Recv pairs.
type HTTPTransport struct {
	endpoint   string
	httpClient *http.Client
	maxBytes   int64

	mu      sync.Mutex
	pending *bytes.Buffer // response body from last Send
}

const (
	DefaultHTTPTimeout      = 60 * time.Second
	DefaultMaxResponseBytes = 16 << 20
)

// NewHTTP creates an HTTPTransport pointing at endpoint.
// endpoint is a full URL, e.g. "http://localhost:8080/mcp".
func NewHTTP(endpoint string) *HTTPTransport {
	return &HTTPTransport{
		endpoint:   endpoint,
		httpClient: &http.Client{Timeout: DefaultHTTPTimeout},
		maxBytes:   DefaultMaxResponseBytes,
	}
}

// NewHTTPWithClient creates an HTTPTransport with a custom http.Client.
// Use this for egress allowlist enforcement.
func NewHTTPWithClient(endpoint string, client *http.Client) *HTTPTransport {
	return &HTTPTransport{
		endpoint:   endpoint,
		httpClient: client,
		maxBytes:   DefaultMaxResponseBytes,
	}
}

// NewHTTPWithLimits creates an HTTPTransport with explicit timeout and body limit.
func NewHTTPWithLimits(endpoint string, timeout time.Duration, maxBytes int64) *HTTPTransport {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponseBytes
	}
	return &HTTPTransport{
		endpoint:   endpoint,
		httpClient: &http.Client{Timeout: timeout},
		maxBytes:   maxBytes,
	}
}

// NewHTTPWithEgress creates an HTTPTransport with egress allowlist enforcement.
// Only hosts in allowedHosts can be dialed; all others are blocked with an error.
// Host comparison is against the hostname only (no port).
func NewHTTPWithEgress(endpoint string, allowedHosts []string) *HTTPTransport {
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, h := range allowedHosts {
		allowed[h] = struct{}{}
	}

	dialer := &net.Dialer{}
	dialCtx := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		if _, ok := allowed[host]; !ok {
			return nil, fmt.Errorf("egress: host %q not in allowlist", host)
		}
		return dialer.DialContext(ctx, network, addr)
	}

	httpClient := &http.Client{
		Timeout: DefaultHTTPTimeout,
		Transport: &http.Transport{
			DialContext: dialCtx,
		},
	}
	return NewHTTPWithClient(endpoint, httpClient)
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

	limited := io.LimitReader(resp.Body, t.maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("http transport: read body: %w", err)
	}
	if int64(len(data)) > t.maxBytes {
		return fmt.Errorf("http transport: response body exceeds %d bytes", t.maxBytes)
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
