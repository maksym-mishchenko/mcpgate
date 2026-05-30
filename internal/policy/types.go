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
	Command   []string             `yaml:"command"`
	Tools     map[string]TargetRule `yaml:"tools"`
	Resources ResourceRule         `yaml:"resources"`
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
