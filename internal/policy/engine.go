package policy

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Verdict int

const (
	VerdictAllow Verdict = iota
	VerdictDeny
	VerdictAsk
	VerdictUnknown // unmatched → human prompt or deny (headless)
)

func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "ALLOW"
	case VerdictDeny:
		return "DENY"
	case VerdictAsk:
		return "ASK"
	default:
		return "UNKNOWN"
	}
}

// Evaluate is a pure function: given a server name, gated method, call name,
// string argument map, and config, it returns a Verdict.
// args is used only for argument-level constraint checking.
func Evaluate(server, method, name string, args map[string]string, cfg *Config) Verdict {
	return EvaluateArgs(server, method, name, ArgsFromStrings(args), cfg)
}

// EvaluateArgs preserves raw JSON argument types for constraint checking.
func EvaluateArgs(server, method, name string, args Args, cfg *Config) Verdict {
	if cfg.Mode == "observe" {
		return VerdictAllow
	}

	srv, ok := cfg.Servers[server]
	if !ok {
		return defaultVerdict(cfg.Default)
	}

	switch method {
	case "tools/call":
		rule, ok := srv.Tools[name]
		if !ok {
			return defaultVerdict(cfg.Default)
		}
		return applyRule(rule.Allow, rule.Constraints, args)

	case "resources/read":
		return applyAllow(srv.Resources.Allow)

	case "sampling/createMessage":
		if srv.Sampling != nil && srv.Sampling.Allow {
			return VerdictAllow
		}
		return VerdictDeny

	case "prompts/get":
		if srv.Prompts != nil && srv.Prompts.Allow {
			return VerdictAllow
		}
		return VerdictDeny

	default:
		return defaultVerdict(cfg.Default)
	}
}

func applyRule(allow Allow, c *Constraints, args Args) Verdict {
	switch allow {
	case AllowFalse:
		return VerdictDeny
	case AllowAsk:
		return VerdictAsk
	case AllowTrue:
		if c != nil {
			if v := checkConstraints(c, args); v != VerdictAllow {
				return v
			}
		}
		return VerdictAllow
	default:
		return VerdictUnknown
	}
}

func applyAllow(a Allow) Verdict {
	switch a {
	case AllowTrue:
		return VerdictAllow
	case AllowFalse:
		return VerdictDeny
	case AllowAsk:
		return VerdictAsk
	default:
		return VerdictUnknown
	}
}

func defaultVerdict(d Allow) Verdict {
	switch d {
	case AllowTrue:
		return VerdictAllow
	case AllowFalse:
		return VerdictDeny
	default:
		return VerdictUnknown
	}
}

func checkConstraints(c *Constraints, args Args) Verdict {
	if c.Path != nil {
		raw, ok := args["path"]
		if !ok {
			return VerdictDeny
		}
		pathVal, ok := stringArg(raw)
		if !ok {
			return VerdictDeny
		}
		if v := checkPathConstraint(c.Path, pathVal); v != VerdictAllow {
			return v
		}
	}
	for field, constraint := range c.Fields {
		raw, ok := args[field]
		if !ok {
			return VerdictDeny
		}
		if !checkFieldConstraint(constraint, raw) {
			return VerdictDeny
		}
	}
	return VerdictAllow
}

func checkPathConstraint(pc *PathConstraint, val string) Verdict {
	if len(pc.Within) > 0 {
		if !pathWithin(val, pc.Within) {
			return VerdictDeny
		}
	}
	if len(pc.ResolveWithin) > 0 {
		if !pathResolveWithin(val, pc.ResolveWithin) {
			return VerdictDeny
		}
	}
	if pc.Equals != "" && val != pc.Equals {
		return VerdictDeny
	}
	if len(pc.OneOf) > 0 {
		found := false
		for _, s := range pc.OneOf {
			if val == s {
				found = true
				break
			}
		}
		if !found {
			return VerdictDeny
		}
	}
	if pc.Matches != "" {
		if !matchesAnchored(pc.Matches, val) {
			return VerdictDeny
		}
	}
	return VerdictAllow
}

func checkFieldConstraint(c FieldConstraint, raw json.RawMessage) bool {
	if c.Equals != "" {
		val, ok := stringArg(raw)
		if !ok || val != c.Equals {
			return false
		}
	}
	if len(c.OneOf) > 0 {
		val, ok := stringArg(raw)
		if !ok {
			return false
		}
		found := false
		for _, allowed := range c.OneOf {
			if val == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if c.Matches != "" {
		val, ok := stringArg(raw)
		if !ok || !matchesAnchored(c.Matches, val) {
			return false
		}
	}
	if c.Min != nil || c.Max != nil {
		n, ok := numberArg(raw)
		if !ok {
			return false
		}
		if c.Min != nil && n < *c.Min {
			return false
		}
		if c.Max != nil && n > *c.Max {
			return false
		}
	}
	if c.Bool != nil {
		b, ok := boolArg(raw)
		if !ok {
			return false
		}
		if b != *c.Bool {
			return false
		}
	}
	return true
}

func stringArg(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func numberArg(raw json.RawMessage) (float64, bool) {
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&n); err == nil {
		f, err := strconv.ParseFloat(n.String(), 64)
		return f, err == nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

func boolArg(raw json.RawMessage) (bool, bool) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, false
	}
	parsed, err := strconv.ParseBool(s)
	return parsed, err == nil
}

// pathWithin returns true only if val is a clean, absolute path that is
// component-wise contained in one of the allowed roots.
// It rejects relative paths, ".." components, and prefix-string tricks like
// "/home/safe-evil" passing a "/home/safe" prefix.
// NOTE: TOCTOU — we check the string; the child process does the actual I/O.
// Symlinks are not resolved here (requires disk access); this is defence-in-depth.
func pathWithin(val string, roots []string) bool {
	if !filepath.IsAbs(val) {
		return false
	}
	clean := filepath.Clean(val)
	// Reject if Clean changed it (had ".." or redundant separators)
	if clean != val {
		return false
	}
	for _, root := range roots {
		cleanRoot := filepath.Clean(root)
		// Component-wise: ensure val starts with root + separator
		if clean == cleanRoot {
			return true
		}
		if strings.HasPrefix(clean, cleanRoot+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func pathResolveWithin(val string, roots []string) bool {
	resolvedVal, err := filepath.EvalSymlinks(val)
	if err != nil {
		return false
	}
	resolvedRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			return false
		}
		resolvedRoots = append(resolvedRoots, resolvedRoot)
	}
	return pathWithin(resolvedVal, resolvedRoots)
}

// matchesAnchored compiles a RE2 pattern anchored at both ends and matches val.
// Input is capped at 4KB to prevent catastrophic backtracking on garbage input.
func matchesAnchored(pattern, val string) bool {
	if len(val) > 4096 {
		return false
	}
	anchored := `\A(?:` + pattern + `)\z`
	re, err := regexp.Compile(anchored)
	if err != nil {
		return false // bad pattern → treat as no match → deny
	}
	return re.MatchString(val)
}
