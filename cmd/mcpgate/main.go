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
	"sort"
	"strings"
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
			dbFlag := fs.String("db", "mcpgate.db", "path to audit database")
			outFlag := fs.String("out", "audit.jsonl", "output file ('-' for stdout)")
			fs.Parse(os.Args[2:]) //nolint:errcheck
			if err := runExport(*dbFlag, *outFlag); err != nil {
				fmt.Fprintf(os.Stderr, "export: %v\n", err)
				os.Exit(1)
			}
			return

		case "discover":
			fs := flag.NewFlagSet("discover", flag.ExitOnError)
			fileFlag := fs.String("file", "-", "verified audit JSON Lines file ('-' for stdin)")
			outFlag := fs.String("out", "draft-policy.yaml", "draft policy output file ('-' for stdout)")
			fs.Parse(os.Args[2:]) //nolint:errcheck
			if err := runDiscover(*fileFlag, *outFlag); err != nil {
				fmt.Fprintf(os.Stderr, "discover: %v\n", err)
				os.Exit(1)
			}
			return

		case "verify":
			fs := flag.NewFlagSet("verify", flag.ExitOnError)
			fileFlag := fs.String("file", "-", "JSON Lines file to verify ('-' for stdin)")
			keyFlag := fs.String("key", "", "optional HMAC key file (32 bytes)")
			fs.Parse(os.Args[2:]) //nolint:errcheck
			if err := runVerify(*fileFlag, *keyFlag); err != nil {
				fmt.Fprintf(os.Stderr, "verify: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	configPath := flag.String("config", "mcpgate.yaml", "path to policy config")
	token := flag.String("token", os.Getenv("MCPGATE_TOKEN"), "bearer token for web UI")
	tokenFile := flag.String("token-file", os.Getenv("MCPGATE_TOKEN_FILE"), "file containing bearer token for web UI")
	auditKey := flag.String("audit-key", os.Getenv("MCPGATE_AUDIT_KEY_FILE"), "32-byte HMAC key file for signing audit rows")
	addr := flag.String("addr", "127.0.0.1:18789", "web server listen address")
	approvalTimeout := flag.Duration("approval-timeout", 30*time.Second, "how long to wait for human approval before auto-deny")
	serverTimeout := flag.Duration("server-timeout", 60*time.Second, "how long to wait for MCP server responses before failing closed")
	serverName := flag.String("server", "", "server name from policy config to run (required when config has multiple servers)")
	flag.Parse()

	serverArgs := flag.Args()

	webToken, err := loadOptionalSecret(*token, *tokenFile, "token")
	if err != nil {
		slog.Error("failed to load token", "err", err)
		os.Exit(1)
	}
	if webToken == "" {
		slog.Error("no token: set --token, --token-file, MCPGATE_TOKEN, or MCPGATE_TOKEN_FILE")
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

	// Require at least one server source: policy config or CLI args.
	if len(cfg.Servers) == 0 && len(serverArgs) == 0 {
		slog.Error("usage: mcpgate [flags] -- <server-command> [args...] (or define servers: in policy config)")
		os.Exit(1)
	}

	// Open audit store.
	store, err := openAuditStore("mcpgate.db", *auditKey)
	if err != nil {
		slog.Error("failed to open audit store", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	// Approval coordinator.
	coord := approval.New()

	// Build the selected server transport from policy config.
	var primaryTransport transport.Transport
	var primaryName string
	var primaryChildDone <-chan struct{} // non-nil only when primary server is a stdio child

	if len(cfg.Servers) > 0 {
		name, srv, selectErr := selectConfiguredServer(cfg.Servers, *serverName)
		if selectErr != nil {
			slog.Error("failed to select server", "err", selectErr)
			os.Exit(1)
		}
		switch srv.TransportKind() {
		case "stdio":
			stdioMgr, startErr := child.Start(ctx, srv.Command)
			if startErr != nil {
				slog.Error("failed to start stdio server", "server", name, "err", startErr)
				os.Exit(1)
			}
			defer stdioMgr.Stop() //nolint:errcheck
			primaryTransport = stdioMgr.Transport()
			primaryChildDone = stdioMgr.Done()
		case "http":
			primaryTransport = transport.NewHTTPWithEgress(srv.URL, srv.EgressAllow)
		default:
			slog.Error("server has no transport configured", "server", name)
			os.Exit(1)
		}
		primaryName = name
	} else {
		if *serverName != "" {
			slog.Error("--server requires servers to be defined in policy config")
			os.Exit(1)
		}
		mgr, startErr := child.Start(ctx, serverArgs)
		if startErr != nil {
			slog.Error("failed to start child", "err", startErr, "args", serverArgs)
			os.Exit(1)
		}
		defer mgr.Stop() //nolint:errcheck
		primaryTransport = mgr.Transport()
		primaryName = serverArgs[0]
		primaryChildDone = mgr.Done()
	}

	// Web server (also serves as the Notifier for the proxy).
	var querier audit.AuditQuerier
	if q, ok := any(store).(audit.AuditQuerier); ok {
		querier = q
	}
	webSrv := web.New(web.Config{
		Token:        webToken,
		Coordinator:  coord,
		AuditQuerier: querier,
	})
	httpServer := &http.Server{
		Addr:    *addr,
		Handler: webSrv.Handler(),
	}
	go func() {
		slog.Info("web server starting", "addr", *addr, "version", version)
		fmt.Fprintf(os.Stderr, "\n  Open: http://%s/?token=%s\n\n", *addr, webToken)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("web server error", "err", err)
		}
	}()

	// Agent transport = mcpgate's own stdin/stdout.
	agentTransport := transport.NewStdio(os.Stdin, os.Stdout)

	// Proxy — wired to the selected server transport.
	p := proxy.New(proxy.Config{
		AgentTransport:  agentTransport,
		ServerTransport: primaryTransport,
		PolicyConfig:    cfg,
		Coordinator:     coord,
		AuditStore:      store,
		ServerName:      primaryName,
		Notifier:        webSrv,
		ApprovalTimeout: *approvalTimeout,
		ServerTimeout:   *serverTimeout,
	})

	// Watch for primary child exit — drain pending approvals and cancel context.
	if primaryChildDone != nil {
		go func() {
			select {
			case <-primaryChildDone:
				slog.Info("child exited — draining approvals")
				coord.DrainAll(approval.VerdictDeny)
				stop()
			case <-ctx.Done():
			}
		}()
	}

	// Run proxy (blocks until ctx is done or transport error).
	p.Run(ctx)

	// Graceful shutdown.
	coord.DrainAll(approval.VerdictDeny)
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	httpServer.Shutdown(shutCtx) //nolint:errcheck
}

func loadOptionalSecret(value, filePath, name string) (string, error) {
	if value != "" && filePath != "" {
		return "", fmt.Errorf("set either --%s or --%s-file, not both", name, name)
	}
	if filePath == "" {
		return value, nil
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read %s file: %w", name, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func openAuditStore(path, keyPath string) (*audit.SQLiteStore, error) {
	if keyPath == "" {
		return audit.Open(path)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read audit key file: %w", err)
	}
	return audit.OpenWithHMAC(path, key)
}

func selectConfiguredServer(servers map[string]policy.ServerConfig, requested string) (string, policy.ServerConfig, error) {
	if requested != "" {
		srv, ok := servers[requested]
		if !ok {
			return "", policy.ServerConfig{}, fmt.Errorf("server %q not found in policy config; available: %s", requested, strings.Join(sortedServerNames(servers), ", "))
		}
		return requested, srv, nil
	}

	names := sortedServerNames(servers)
	switch len(names) {
	case 0:
		return "", policy.ServerConfig{}, fmt.Errorf("no servers defined in policy config")
	case 1:
		name := names[0]
		return name, servers[name], nil
	default:
		return "", policy.ServerConfig{}, fmt.Errorf("multiple servers configured (%s); set --server to choose one", strings.Join(names, ", "))
	}
}

func sortedServerNames(servers map[string]policy.ServerConfig) []string {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
