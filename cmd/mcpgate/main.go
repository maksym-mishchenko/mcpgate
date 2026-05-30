package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/maksym-mishchenko/mcpgate/internal/approval"
	"github.com/maksym-mishchenko/mcpgate/internal/audit"
	"github.com/maksym-mishchenko/mcpgate/internal/child"
	"github.com/maksym-mishchenko/mcpgate/internal/policy"
	"github.com/maksym-mishchenko/mcpgate/internal/proxy"
	"github.com/maksym-mishchenko/mcpgate/internal/transport"
	"github.com/maksym-mishchenko/mcpgate/internal/web"
)

func main() {
	configPath := flag.String("config", "mcpgate.yaml", "path to policy config")
	token := flag.String("token", os.Getenv("MCPGATE_TOKEN"), "bearer token for web UI")
	addr := flag.String("addr", "127.0.0.1:18789", "web server listen address")
	flag.Parse()

	serverArgs := flag.Args()
	if len(serverArgs) == 0 {
		slog.Error("usage: mcpgate [flags] -- <server-command> [args...]")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Load policy.
	cfg, err := policy.Load(*configPath)
	if err != nil {
		slog.Error("failed to load policy", "err", err, "path", *configPath)
		os.Exit(1)
	}

	// Open audit store.
	store, err := audit.Open("mcpgate.db")
	if err != nil {
		slog.Error("failed to open audit store", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	// Start child process.
	mgr, err := child.Start(ctx, serverArgs)
	if err != nil {
		slog.Error("failed to start child", "err", err, "args", serverArgs)
		os.Exit(1)
	}
	defer mgr.Stop() //nolint:errcheck

	// Approval coordinator.
	coord := approval.New()

	// Agent transport = mcpgate's own stdin/stdout.
	agentTransport := transport.NewStdio(os.Stdin, os.Stdout)

	// Proxy.
	p := proxy.New(proxy.Config{
		AgentTransport:  agentTransport,
		ServerTransport: mgr.Transport(),
		PolicyConfig:    cfg,
		Coordinator:     coord,
		AuditStore:      store,
		ServerName:      serverArgs[0],
	})

	// Web server.
	webSrv := web.New(web.Config{
		Token:       *token,
		Coordinator: coord,
	})
	httpServer := &http.Server{
		Addr:    *addr,
		Handler: webSrv.Handler(),
	}
	go func() {
		slog.Info("web server starting", "addr", *addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("web server error", "err", err)
		}
	}()

	// Watch for child exit — drain pending approvals and cancel context.
	go func() {
		select {
		case <-mgr.Done():
			slog.Info("child exited — draining approvals")
			coord.DrainAll(approval.VerdictDeny)
			stop()
		case <-ctx.Done():
		}
	}()

	// Run proxy (blocks until ctx is done or transport error).
	p.Run(ctx)

	// Graceful shutdown.
	coord.DrainAll(approval.VerdictDeny)
	httpServer.Shutdown(context.Background()) //nolint:errcheck
}
