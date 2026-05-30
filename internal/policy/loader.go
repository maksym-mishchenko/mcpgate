package policy

import (
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Load parses a policy YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Mode == "" {
		cfg.Mode = "observe"
	}
	return &cfg, nil
}

// HotLoader holds the latest parsed Config and reloads on mtime change.
type HotLoader struct {
	mu    sync.RWMutex
	path  string
	cfg   *Config
	mtime time.Time
}

func NewHotLoader(path string) (*HotLoader, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	info, _ := os.Stat(path)
	return &HotLoader{path: path, cfg: cfg, mtime: info.ModTime()}, nil
}

// Get returns the current config, reloading from disk if the file has changed.
func (h *HotLoader) Get() *Config {
	info, err := os.Stat(h.path)
	if err != nil {
		h.mu.RLock()
		defer h.mu.RUnlock()
		return h.cfg
	}
	h.mu.RLock()
	if !info.ModTime().After(h.mtime) {
		cfg := h.cfg
		h.mu.RUnlock()
		return cfg
	}
	h.mu.RUnlock()

	// Reload needed.
	newCfg, err := Load(h.path)
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		h.cfg = newCfg
		h.mtime = info.ModTime()
	}
	return h.cfg
}
