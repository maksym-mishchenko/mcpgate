package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

// runKeygen writes 32 random bytes to path with mode 0400.
// Returns error if path already exists (never overwrite a key).
func runKeygen(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("key file already exists: %s (delete it first if you want to rotate)", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat key file: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	if err := os.WriteFile(path, key, 0400); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}
