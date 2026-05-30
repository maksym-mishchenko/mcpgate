package proxy

import (
	"sync"

	"github.com/maksym-mishchenko/mcpgate/internal/transport"
)

// Router holds named transports and routes calls to them.
type Router struct {
	mu         sync.RWMutex
	transports map[string]transport.Transport
}

// NewRouter creates an empty Router.
func NewRouter() *Router {
	return &Router{transports: make(map[string]transport.Transport)}
}

// Add registers a named transport. Overwrites if name already exists.
func (r *Router) Add(name string, t transport.Transport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transports[name] = t
}

// Get returns the transport for name, or (nil, false) if not found.
func (r *Router) Get(name string) (transport.Transport, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.transports[name]
	return t, ok
}

// Names returns all registered server names.
func (r *Router) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.transports))
	for k := range r.transports {
		names = append(names, k)
	}
	return names
}
