package policy

// Allow values for a rule.
type Allow string

const (
	AllowTrue  Allow = "true"
	AllowFalse Allow = "false"
	AllowAsk   Allow = "ask"
)

type Config struct {
	Version int                     `yaml:"version"`
	Mode    string                  `yaml:"mode"`    // "observe" | "enforce"
	Default Allow                   `yaml:"default"` // default verdict for unmatched
	Servers map[string]ServerConfig `yaml:"servers"`
}

type ServerConfig struct {
	Command     []string              `yaml:"command"`
	URL         string                `yaml:"url,omitempty"`          // HTTP transport endpoint
	EgressAllow []string              `yaml:"egress_allow,omitempty"` // hostname allowlist for HTTP transport
	Tools       map[string]TargetRule `yaml:"tools"`
	Resources   ResourceRule          `yaml:"resources"`
	Sampling    *SamplingRule         `yaml:"sampling,omitempty"`
	Prompts     *PromptsRule          `yaml:"prompts,omitempty"`
}

// SamplingRule controls whether this server may send sampling/createMessage requests to the agent.
type SamplingRule struct {
	Allow bool `yaml:"allow"`
}

// PromptsRule controls whether the agent may call prompts/get on this server.
type PromptsRule struct {
	Allow bool `yaml:"allow"`
}

// TransportKind returns "stdio" if Command is set, "http" if URL is set, or "" if neither.
func (s ServerConfig) TransportKind() string {
	if len(s.Command) > 0 {
		return "stdio"
	}
	if s.URL != "" {
		return "http"
	}
	return ""
}

type TargetRule struct {
	Allow       Allow        `yaml:"allow"`
	Constraints *Constraints `yaml:"constraints,omitempty"`
}

type ResourceRule struct {
	Allow Allow `yaml:"allow"`
}

type Constraints struct {
	Path *PathConstraint `yaml:"path,omitempty"`
}

type PathConstraint struct {
	Within  []string `yaml:"within,omitempty"`
	Matches string   `yaml:"matches,omitempty"`
	Equals  string   `yaml:"equals,omitempty"`
	OneOf   []string `yaml:"one_of,omitempty"`
}
