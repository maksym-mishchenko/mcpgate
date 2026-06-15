package web_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maksym-mishchenko/mcpgate/internal/approval"
	"github.com/maksym-mishchenko/mcpgate/internal/event"
	"github.com/maksym-mishchenko/mcpgate/internal/web"
)

const testToken = "test-secret-token"

func makeServer() *web.Server {
	coord := approval.New()
	return web.New(web.Config{
		Token:       testToken,
		Coordinator: coord,
		// AuditQuerier: nil (intentional for most tests)
	})
}

func TestHealthEndpoint(t *testing.T) {
	coord := approval.New()
	s := web.New(web.Config{
		Token:       testToken,
		Coordinator: coord,
		Health: web.HealthInfo{
			Version:    "test-version",
			ServerName: "fs",
			PolicyStatus: func() web.PolicyStatus {
				return web.PolicyStatus{
					Path:                  "mcpgate.yaml",
					Mode:                  "enforce",
					Reload:                "hot-last-known-good",
					HeuristicsEnabled:     true,
					HeuristicsBlockOnWarn: true,
				}
			},
			Audit: web.AuditStatus{History: true, HMAC: true},
		},
	})
	s.AddPending("fs:1", event.PendingCall{Key: "fs:1"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Host = "localhost"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("health: status = %d, want 200", rec.Code)
	}
	var got struct {
		Status  string `json:"status"`
		Version string `json:"version"`
		Server  string `json:"server"`
		Policy  struct {
			Path                  string `json:"path"`
			Mode                  string `json:"mode"`
			Reload                string `json:"reload"`
			HeuristicsEnabled     bool   `json:"heuristics_enabled"`
			HeuristicsBlockOnWarn bool   `json:"heuristics_block_on_warn"`
		} `json:"policy"`
		Audit struct {
			History bool `json:"history"`
			HMAC    bool `json:"hmac"`
		} `json:"audit"`
		Runtime struct {
			Pending int `json:"pending"`
		} `json:"runtime"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if got.Status != "ok" || got.Version != "test-version" || got.Server != "fs" {
		t.Fatalf("unexpected health identity: %+v", got)
	}
	if got.Policy.Path != "mcpgate.yaml" || got.Policy.Mode != "enforce" || got.Policy.Reload != "hot-last-known-good" {
		t.Fatalf("unexpected policy health: %+v", got.Policy)
	}
	if !got.Policy.HeuristicsEnabled || !got.Policy.HeuristicsBlockOnWarn {
		t.Fatalf("unexpected heuristic health: %+v", got.Policy)
	}
	if !got.Audit.History || !got.Audit.HMAC {
		t.Fatalf("unexpected audit health: %+v", got.Audit)
	}
	if got.Runtime.Pending != 1 {
		t.Fatalf("pending = %d, want 1", got.Runtime.Pending)
	}
}

func TestNoTokenReturns401(t *testing.T) {
	s := makeServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = "localhost"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
}

func TestWrongTokenReturns401(t *testing.T) {
	s := makeServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.Host = "localhost"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", rec.Code)
	}
}

func TestBadHostReturns403(t *testing.T) {
	s := makeServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Host = "evil.example.com"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("bad host: status = %d, want 403", rec.Code)
	}
}

func TestTokenQueryParam(t *testing.T) {
	s := makeServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health?token="+testToken, nil)
	req.Host = "127.0.0.1"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("token query param: status = %d, want 200", rec.Code)
	}
}

func TestApproveEndpoint(t *testing.T) {
	coord := approval.New()
	s := web.New(web.Config{Token: testToken, Coordinator: coord})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resultCh := make(chan approval.Verdict, 1)
	go func() {
		v, _ := coord.Park(ctx, "key1")
		resultCh <- v
	}()
	time.Sleep(10 * time.Millisecond)

	body, _ := json.Marshal(map[string]string{"key": "key1", "verdict": "allow"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "localhost"
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("approve: status = %d, want 200", rec.Code)
	}
	select {
	case v := <-resultCh:
		if v != approval.VerdictAllow {
			t.Errorf("verdict = %v, want VerdictAllow", v)
		}
	case <-time.After(time.Second):
		t.Error("coord.Park did not unblock")
	}
}

func TestSSEContentType(t *testing.T) {
	s := makeServer()
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/events?token="+testToken, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil && !strings.Contains(err.Error(), "context") {
		t.Fatalf("GET /events: %v", err)
	}
	if resp != nil {
		defer resp.Body.Close()
		ct := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "text/event-stream") {
			t.Errorf("Content-Type = %q, want text/event-stream", ct)
		}
	}
}

func TestSSEBroadcast(t *testing.T) {
	s := makeServer()
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/events?token="+testToken, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	defer resp.Body.Close()

	time.Sleep(20 * time.Millisecond) // let client register

	s.Broadcast("audit", map[string]string{"method": "tools/call"})

	scanner := bufio.NewScanner(resp.Body)
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for scanner.Scan() {
			line := scanner.Text()
			lines = append(lines, line)
			if line == "" && len(lines) > 1 {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("no SSE event received within 2s")
	}

	found := false
	for _, l := range lines {
		if strings.Contains(l, "tools/call") {
			found = true
		}
	}
	if !found {
		t.Errorf("SSE event missing broadcast data; lines: %v", lines)
	}
}

func TestAddRemovePending(t *testing.T) {
	s := makeServer()

	s.AddPending("fs:1", event.PendingCall{Key: "fs:1", Name: "read_file"})
	s.AddPending("fs:2", event.PendingCall{Key: "fs:2", Name: "write_file"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/pending?token="+testToken, nil)
	req.Host = "localhost"
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var calls []event.PendingCall
	if err := json.NewDecoder(rec.Body).Decode(&calls); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(calls) != 2 {
		t.Errorf("len = %d, want 2", len(calls))
	}

	s.RemovePending("fs:1")

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/pending?token="+testToken, nil)
	req2.Host = "localhost"
	s.Handler().ServeHTTP(rec2, req2)

	var calls2 []event.PendingCall
	json.NewDecoder(rec2.Body).Decode(&calls2) //nolint:errcheck
	if len(calls2) != 1 {
		t.Errorf("after remove: len = %d, want 1", len(calls2))
	}
}

func TestAuditEndpointWithNilQuerier(t *testing.T) {
	s := makeServer() // no AuditQuerier configured
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/audit?token="+testToken, nil)
	req.Host = "localhost"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := strings.TrimSpace(rec.Body.String())
	if body != "[]" {
		t.Errorf("body = %q, want []", body)
	}
}
