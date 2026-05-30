package main

import (
	"fmt"
	"os"

	"github.com/maksym-mishchenko/mcpgate/internal/audit"
)

// runExport opens dbPath, exports audit chain as JSON Lines to outPath.
// If outPath is "-", writes to stdout.
func runExport(dbPath, outPath string) error {
	store, err := audit.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer store.Close()

	var w *os.File
	if outPath == "-" {
		w = os.Stdout
	} else {
		w, err = os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer w.Close()
	}

	return store.Export(w)
}
