package workflow

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Workflow represents a complete workflow definition
type Workflow struct {
	Name      string            `yaml:"name"`
	BeaconID  string            `yaml:"beacon_id,omitempty"`  // Optional - if empty, will prompt user
	Variables map[string]string `yaml:"variables,omitempty"`  // User-defined variables for interpolation
	Actions   []Action          `yaml:"actions"`
	Parallel  bool              `yaml:"parallel,omitempty"` // Execute all actions in parallel
}

// Action represents a single action in the workflow
type Action struct {
	Name       string                 `yaml:"name"`
	Type       string                 `yaml:"type"`
	Parameters map[string]interface{} `yaml:"parameters,omitempty"`
	Conditions []Condition            `yaml:"conditions,omitempty"` // All must be true (AND logic) - deprecated, use ConditionGroups
	AnyOf      []Condition            `yaml:"any_of,omitempty"`     // At least one must be true (OR logic)
	AllOf      []Condition            `yaml:"all_of,omitempty"`     // All must be true (AND logic)
	OnSuccess  []Action               `yaml:"on_success,omitempty"`
	OnFailure  []Action               `yaml:"on_failure,omitempty"`
}

// Condition represents a condition to check before executing an action
type Condition struct {
	Type          string      `yaml:"type"`
	Source        string      `yaml:"source"`                    // which previous action output or beacon field to check (e.g., "check_user" or "beacon.user")
	Field         string      `yaml:"field,omitempty"`           // deprecated: use source with beacon.field syntax instead
	Operator      string      `yaml:"operator"`                  // contains, equals, matches, etc.
	Value         string      `yaml:"value"`                     // value to compare against
	CaseSensitive bool        `yaml:"case_sensitive,omitempty"`
	AnyOf         []Condition `yaml:"any_of,omitempty"`          // Nested OR conditions
	AllOf         []Condition `yaml:"all_of,omitempty"`          // Nested AND conditions
}

// LoadWorkflow loads a workflow from a YAML file
func LoadWorkflow(filename string) (*Workflow, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var wf Workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, err
	}

	return &wf, nil
}
