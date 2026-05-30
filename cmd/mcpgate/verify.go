package main

import (
	"fmt"
	"os"

	"github.com/maksym-mishchenko/mcpgate/internal/audit"
)

// runVerify verifies the audit chain from filePath.
// keyPath is optional ("" = no HMAC check).
func runVerify(filePath, keyPath string) error {
	var key []byte
	if keyPath != "" {
		var err error
		key, err = os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}
		if len(key) != 32 {
			return fmt.Errorf("key file must be 32 bytes, got %d", len(key))
		}
	}

	var f *os.File
	if filePath == "-" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(filePath)
		if err != nil {
			return fmt.Errorf("open file: %w", err)
		}
		defer f.Close()
	}

	ok, err := audit.VerifyFile(f, key)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "FAIL: chain integrity check failed — tampering detected")
		os.Exit(2)
	}
	fmt.Println("OK: chain integrity verified")
	return nil
}
