package approval_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/maksym-mishchenko/mcpgate/internal/approval"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestParkAndResolve(t *testing.T) {
	c := approval.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		v, err := c.Park(ctx, "fs:1")
		if err != nil {
			t.Errorf("Park: %v", err)
			return
		}
		if v != approval.VerdictAllow {
			t.Errorf("Park verdict = %v", v)
		}
	}()

	time.Sleep(10 * time.Millisecond)
	c.Resolve("fs:1", approval.VerdictAllow)
	wg.Wait()
}

func TestParkTimeout(t *testing.T) {
	c := approval.New()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	v, err := c.Park(ctx, "fs:timeout")
	if err == nil {
		t.Errorf("expected timeout error, verdict = %v", v)
	}
}

func TestDoubleResolveNoBlock(t *testing.T) {
	c := approval.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.Park(ctx, "fs:dbl") //nolint
	}()

	time.Sleep(10 * time.Millisecond)
	c.Resolve("fs:dbl", approval.VerdictAllow)
	// Second resolve must not block or panic.
	c.Resolve("fs:dbl", approval.VerdictDeny)
	cancel()
	wg.Wait()
}

func TestDrainOnCrash(t *testing.T) {
	c := approval.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		key := "fs:" + string(rune('0'+i))
		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			c.Park(ctx, k) //nolint
		}(key)
	}

	time.Sleep(20 * time.Millisecond)
	c.DrainAll(approval.VerdictDeny) // simulate child crash
	wg.Wait()
}
