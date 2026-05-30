package approval

import (
	"context"
	"fmt"
	"sync"
)

type Verdict int

const (
	VerdictAllow Verdict = iota
	VerdictDeny
)

func (v Verdict) String() string {
	if v == VerdictAllow {
		return "ALLOW"
	}
	return "DENY"
}

type entry struct {
	ch   chan Verdict // buffered cap 1
	once sync.Once
}

// Coordinator parks calls awaiting human approval and resumes them with a verdict.
type Coordinator struct {
	mu      sync.Mutex
	pending map[string]*entry
}

func New() *Coordinator {
	return &Coordinator{pending: make(map[string]*entry)}
}

// Park blocks until the call is resolved (human response or context expiry).
// key must be unique per call: "serverName:requestID".
func (c *Coordinator) Park(ctx context.Context, key string) (Verdict, error) {
	ch := make(chan Verdict, 1)
	e := &entry{ch: ch}

	c.mu.Lock()
	c.pending[key] = e
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pending, key)
		c.mu.Unlock()
	}()

	select {
	case v := <-ch:
		return v, nil
	case <-ctx.Done():
		return VerdictDeny, fmt.Errorf("approval timeout: %w", ctx.Err())
	}
}

// Resolve delivers a verdict to the waiting Park call.
// Safe to call multiple times (only first delivery takes effect).
func (c *Coordinator) Resolve(key string, v Verdict) {
	c.mu.Lock()
	e, ok := c.pending[key]
	c.mu.Unlock()
	if !ok {
		return
	}
	e.once.Do(func() {
		e.ch <- v
	})
}

// DrainAll resolves all pending calls with the given verdict.
// Call when the child process crashes so no goroutines leak.
func (c *Coordinator) DrainAll(v Verdict) {
	c.mu.Lock()
	keys := make([]string, 0, len(c.pending))
	for k := range c.pending {
		keys = append(keys, k)
	}
	c.mu.Unlock()
	for _, k := range keys {
		c.Resolve(k, v)
	}
}
