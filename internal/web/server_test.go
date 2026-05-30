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
	"github.com/maksym-mishchenko/mcpgate/internal/web"
)

const testToken = "test-secret-token"

func makeServer() *web.Server {
	coord := approval.New()
	return web.New(web.Config{Token: testToken, Coordinator: coord})
}

func TestHealthEndpoint(t *testing.T) {
	s := makeServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Host = "localhost"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("health: status = %d, want 200", rec.Code)
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
