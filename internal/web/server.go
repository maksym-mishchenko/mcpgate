package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/maksym-mishchenko/mcpgate/internal/approval"
	"github.com/maksym-mishchenko/mcpgate/internal/audit"
	"github.com/maksym-mishchenko/mcpgate/internal/event"
)

//go:embed static
var staticFiles embed.FS

// Config holds server configuration.
type Config struct {
	Token        string
	Coordinator  *approval.Coordinator
	AuditQuerier audit.AuditQuerier // optional; nil disables /audit history
}

// Server is the HTTP server for mcpgate's web UI and approval API.
// It implements event.Notifier.
type Server struct {
	token   string
	coord   *approval.Coordinator
	querier audit.AuditQuerier
	mux     *http.ServeMux

	mu      sync.Mutex
	clients map[chan []byte]struct{}
	pending map[string]event.PendingCall
}

// New creates a new Server.
func New(cfg Config) *Server {
	s := &Server{
		token:   cfg.Token,
		coord:   cfg.Coordinator,
		querier: cfg.AuditQuerier,
		mux:     http.NewServeMux(),
		clients: make(map[chan []byte]struct{}),
		pending: make(map[string]event.PendingCall),
	}
	// Static UI.
	sub, _ := fs.Sub(staticFiles, "static")
	s.mux.Handle("/", http.FileServer(http.FS(sub)))
	// API endpoints (all require auth).
	s.mux.HandleFunc("/health", s.auth(s.handleHealth))
	s.mux.HandleFunc("/approve", s.auth(s.handleApprove))
	s.mux.HandleFunc("/events", s.auth(s.handleEvents))
	s.mux.HandleFunc("/pending", s.auth(s.handlePending))
	s.mux.HandleFunc("/audit", s.auth(s.handleAudit))
	return s
}

// Handler returns the http.Handler for use with http.Server.
func (s *Server) Handler() http.Handler { return s.mux }

// --- event.Notifier implementation ---

// Broadcast sends an SSE event to all connected clients.
func (s *Server) Broadcast(evtName string, data any) {
	payload, err := json.Marshal(data)
	if err != nil {
		slog.Error("broadcast marshal failed", "err", err)
		return
	}
	msg := []byte("event: " + evtName + "\ndata: " + string(payload) + "\n\n")
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- msg:
		default: // client too slow; drop
		}
	}
}

// AddPending registers a parked call so reconnecting clients can see it.
func (s *Server) AddPending(key string, c event.PendingCall) {
	s.mu.Lock()
	s.pending[key] = c
	s.mu.Unlock()
}

// RemovePending removes a parked call once resolved.
func (s *Server) RemovePending(key string) {
	s.mu.Lock()
	delete(s.pending, key)
	s.mu.Unlock()
}

// --- auth middleware ---

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
		if host != "localhost" && host != "127.0.0.1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		token := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		} else {
			token = r.URL.Query().Get("token")
		}
		if !tokenMatches(token, s.token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func tokenMatches(got, want string) bool {
	gotSum := sha256.Sum256([]byte(got))
	wantSum := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotSum[:], wantSum[:]) == 1
}

// --- handlers ---

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

func (s *Server) handlePending(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	calls := make([]event.PendingCall, 0, len(s.pending))
	for _, c := range s.pending {
		calls = append(calls, c)
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(calls) //nolint:errcheck
}

func (s *Server) handleAudit(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.querier == nil {
		w.Write([]byte("[]")) //nolint:errcheck
		return
	}
	entries, err := s.querier.Recent(100)
	if err != nil {
		slog.Error("audit recent query failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []audit.Entry{}
	}
	json.NewEncoder(w).Encode(entries) //nolint:errcheck
}
