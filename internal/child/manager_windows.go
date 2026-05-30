//go:build windows

package child

import (
	"context"
	"os/exec"
	"time"

	"github.com/maksym-mishchenko/mcpgate/internal/transport"
)

// Manager manages a single child MCP server process.
type Manager struct {
	cmd   *exec.Cmd
	trans transport.Transport
	done  chan struct{}
}

// Start spawns the process defined by args (args[0] = executable).
func Start(ctx context.Context, args []string) (*Manager, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	trans := transport.NewStdio(stdout, stdin)
	done := make(chan struct{})

	m := &Manager{cmd: cmd, trans: trans, done: done}

	go func() {
		cmd.Wait() //nolint:errcheck
		close(done)
	}()

	return m, nil
}

// Transport returns the transport connected to the child's stdin/stdout.
func (m *Manager) Transport() transport.Transport { return m.trans }

// Done returns a channel that is closed when the process exits.
func (m *Manager) Done() <-chan struct{} { return m.done }

// Stop kills the process. Windows does not support process groups, so we kill
// the process directly and wait up to 3 seconds for it to exit.
func (m *Manager) Stop() error {
	if m.cmd.Process == nil {
		return nil
	}
	m.cmd.Process.Kill() //nolint:errcheck

	select {
	case <-m.done:
	case <-time.After(3 * time.Second):
		<-m.done
	}
	return nil
}
