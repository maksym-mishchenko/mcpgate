package policy

import (
	"path/filepath"
	"regexp"
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
// argument map, and config, it returns a Verdict.
// args is used only for argument-level constraint checking.
func Evaluate(server, method, name string, args map[string]string, cfg *Config) Verdict {
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

func applyRule(allow Allow, c *Constraints, args map[string]string) Verdict {
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

func checkConstraints(c *Constraints, args map[string]string) Verdict {
	if c.Path == nil {
		return VerdictAllow
	}
	pathVal, ok := args["path"]
	if !ok {
		return VerdictAllow // no path arg → constraint not applicable
	}
	return checkPathConstraint(c.Path, pathVal)
}

func checkPathConstraint(pc *PathConstraint, val string) Verdict {
	if len(pc.Within) > 0 {
		if !pathWithin(val, pc.Within) {
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
