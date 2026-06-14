package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/maksym-mishchenko/mcpgate/internal/audit"
)

type discoveredServer struct {
	tools     map[string]struct{}
	resources bool
	prompts   bool
	sampling  bool
}

type discoveryResult struct {
	servers         map[string]*discoveredServer
	allowedRows     int
	skippedWarnings int
}

func runDiscover(filePath, outPath string) error {
	in, err := openInput(filePath)
	if err != nil {
		return err
	}
	if in != os.Stdin {
		defer in.Close()
	}

	result, err := discoverPolicy(in)
	if err != nil {
		return err
	}

	var out *os.File
	if outPath == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer out.Close()
	}

	if err := writeDraftPolicy(out, result); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "discover: wrote %d allowed rows", result.allowedRows)
	if result.skippedWarnings > 0 {
		fmt.Fprintf(os.Stderr, ", skipped %d warning rows", result.skippedWarnings)
	}
	fmt.Fprintln(os.Stderr)
	return nil
}

func openInput(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	return f, nil
}

func discoverPolicy(r io.Reader) (discoveryResult, error) {
	result := discoveryResult{servers: make(map[string]*discoveredServer)}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var row audit.ExportedRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return result, fmt.Errorf("line %d: invalid JSONL audit row: %w", lineNum, err)
		}
		if row.Method == "GENESIS" || row.Verdict != "ALLOW" || row.Server == "" {
			continue
		}
		if row.Warnings != "" {
			result.skippedWarnings++
			continue
		}

		switch row.Method {
		case "tools/call":
			if row.Name == "" {
				continue
			}
			srv := result.server(row.Server)
			srv.tools[row.Name] = struct{}{}
			result.allowedRows++
		case "resources/read":
			srv := result.server(row.Server)
			srv.resources = true
			result.allowedRows++
		case "prompts/get":
			srv := result.server(row.Server)
			srv.prompts = true
			result.allowedRows++
		case "sampling/createMessage":
			srv := result.server(row.Server)
			srv.sampling = true
			result.allowedRows++
		}
	}
	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("read audit export: %w", err)
	}
	if result.allowedRows == 0 {
		return result, fmt.Errorf("no warning-free ALLOW rows found in audit export")
	}
	return result, nil
}

func (r discoveryResult) server(name string) *discoveredServer {
	srv := r.servers[name]
	if srv == nil {
		srv = &discoveredServer{tools: make(map[string]struct{})}
		r.servers[name] = srv
	}
	return srv
}

func writeDraftPolicy(w io.Writer, result discoveryResult) error {
	var b strings.Builder
	b.WriteString("# Draft policy generated from a verified mcpgate audit export.\n")
	b.WriteString("# Review before use: observed calls are not automatically safe, and path/field constraints are not inferred.\n")
	b.WriteString("version: 1\n")
	b.WriteString("mode: enforce\n")
	b.WriteString("default: \"false\"\n\n")
	b.WriteString("servers:\n")

	for _, server := range sortedMapKeys(result.servers) {
		srv := result.servers[server]
		b.WriteString("  ")
		b.WriteString(yamlString(server))
		b.WriteString(":\n")
		b.WriteString("    # Replace with the real stdio command or change to url/egress_allow for HTTP transport.\n")
		b.WriteString("    command: [\"REPLACE_WITH_SERVER_COMMAND\"]\n")
		if len(srv.tools) > 0 {
			b.WriteString("    tools:\n")
			for _, tool := range sortedSetKeys(srv.tools) {
				b.WriteString("      ")
				b.WriteString(yamlString(tool))
				b.WriteString(":\n")
				b.WriteString("        allow: \"true\"\n")
			}
		}
		b.WriteString("    resources:\n")
		b.WriteString("      allow: ")
		b.WriteString(yamlAllow(srv.resources))
		b.WriteString("\n")
		if srv.prompts {
			b.WriteString("    prompts:\n")
			b.WriteString("      allow: true\n")
		}
		if srv.sampling {
			b.WriteString("    sampling:\n")
			b.WriteString("      allow: true\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("heuristics:\n")
	b.WriteString("  enabled: true\n")
	b.WriteString("  block_on_warn: false\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func yamlAllow(allowed bool) string {
	if allowed {
		return "\"true\""
	}
	return "\"false\""
}

func yamlString(s string) string {
	return strconv.Quote(s)
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedSetKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
