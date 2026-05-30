package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/maksym-mishchenko/mcpgate/internal/approval"
)

// Config holds server configuration.
type Config struct {
	Token       string
	Coordinator *approval.Coordinator
}

// Server is the HTTP server for mcpgate's web UI and approval API.
type Server struct {
	token string
	coord *approval.Coordinator
	mux   *http.ServeMux

	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

// New creates a new Server with the given config.
func New(cfg Config) *Server {
	s := &Server{
		token:   cfg.Token,
		coord:   cfg.Coordinator,
		mux:     http.NewServeMux(),
		clients: make(map[chan []byte]struct{}),
	}
	s.mux.HandleFunc("/health", s.auth(s.handleHealth))
	s.mux.HandleFunc("/approve", s.auth(s.handleApprove))
	s.mux.HandleFunc("/events", s.auth(s.handleEvents))
	return s
}

// Handler returns the http.Handler for use with http.Server.
func (s *Server) Handler() http.Handler { return s.mux }

// Broadcast sends an SSE event to all connected clients.
func (s *Server) Broadcast(event string, data any) {
	payload, err := json.Marshal(data)
	if err != nil {
		slog.Error("broadcast marshal failed", "err", err)
		return
	}
	msg := []byte("event: " + event + "\ndata: " + string(payload) + "\n\n")
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- msg:
		default: // client too slow; drop
		}
	}
}

// auth is middleware that checks token (Bearer or ?token=) and Host header.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Host check (anti-DNS-rebinding)
		host := r.Host
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
		if host != "localhost" && host != "127.0.0.1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Token check
		token := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		} else {
			token = r.URL.Query().Get("token")
		}
		if token != s.token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Key     string `json:"key"`
		Verdict string `json:"verdict"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var v approval.Verdict
	switch strings.ToLower(body.Verdict) {
	case "allow":
		v = approval.VerdictAllow
	case "deny":
		v = approval.VerdictDeny
	default:
		http.Error(w, "verdict must be allow or deny", http.StatusBadRequest)
		return
	}
	s.coord.Resolve(body.Key, v)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch := make(chan []byte, 16)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	for {
		select {
		case msg := <-ch:
			w.Write(msg) //nolint:errcheck
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
