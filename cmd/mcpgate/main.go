// cmd/mcpgate/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/maksym-mishchenko/mcpgate/internal/approval"
	"github.com/maksym-mishchenko/mcpgate/internal/audit"
	"github.com/maksym-mishchenko/mcpgate/internal/child"
	"github.com/maksym-mishchenko/mcpgate/internal/policy"
	"github.com/maksym-mishchenko/mcpgate/internal/proxy"
	"github.com/maksym-mishchenko/mcpgate/internal/transport"
	"github.com/maksym-mishchenko/mcpgate/internal/web"
)

// version is stamped by GoReleaser via ldflags.
var version = "dev"

func main() {
	// Subcommand dispatch — must come before flag.Parse() to allow per-subcommand flags.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "keygen":
			if len(os.Args) < 3 {
				fmt.Fprintln(os.Stderr, "usage: mcpgate keygen <key-file>")
				os.Exit(1)
			}
			if err := runKeygen(os.Args[2]); err != nil {
				fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "key written to %s\n", os.Args[2])
			return

		case "export":
			fs := flag.NewFlagSet("export", flag.ExitOnError)
			dbFlag  := fs.String("db",  "mcpgate.db",      "path to audit database")
			outFlag := fs.String("out", "audit.jsonl", "output file ('-' for stdout)")
			fs.Parse(os.Args[2:]) //nolint:errcheck
			if err := runExport(*dbFlag, *outFlag); err != nil {
				fmt.Fprintf(os.Stderr, "export: %v\n", err)
				os.Exit(1)
			}
			return

		case "verify":
			fs := flag.NewFlagSet("verify", flag.ExitOnError)
			fileFlag := fs.String("file", "-",  "JSON Lines file to verify ('-' for stdin)")
			keyFlag  := fs.String("key",  "",   "optional HMAC key file (32 bytes)")
			fs.Parse(os.Args[2:]) //nolint:errcheck
			if err := runVerify(*fileFlag, *keyFlag); err != nil {
				fmt.Fprintf(os.Stderr, "verify: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	configPath      := flag.String("config", "mcpgate.yaml", "path to policy config")
	token           := flag.String("token", os.Getenv("MCPGATE_TOKEN"), "bearer token for web UI")
	addr            := flag.String("addr", "127.0.0.1:18789", "web server listen address")
	approvalTimeout := flag.Duration("approval-timeout", 30*time.Second, "how long to wait for human approval before auto-deny")
	flag.Parse()

	serverArgs := flag.Args()
	if len(serverArgs) == 0 {
		slog.Error("usage: mcpgate [flags] -- <server-command> [args...]")
		os.Exit(1)
	}

	if *token == "" {
		slog.Error("no token: set --token or MCPGATE_TOKEN env var")
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

	// Web server (also serves as the Notifier for the proxy).
	var querier audit.AuditQuerier
	if q, ok := any(store).(audit.AuditQuerier); ok {
		querier = q
	}
	webSrv := web.New(web.Config{
		Token:        *token,
		Coordinator:  coord,
		AuditQuerier: querier,
	})
	httpServer := &http.Server{
		Addr:    *addr,
		Handler: webSrv.Handler(),
	}
	go func() {
		slog.Info("web server starting", "addr", *addr, "version", version)
		fmt.Fprintf(os.Stderr, "\n  Open: http://%s/?token=%s\n\n", *addr, *token)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("web server error", "err", err)
		}
	}()

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
		Notifier:        webSrv,
		ApprovalTimeout: *approvalTimeout,
	})

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
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	httpServer.Shutdown(shutCtx) //nolint:errcheck
}
