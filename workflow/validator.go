package workflow

import (
	"context"
	"fmt"
	"os"
	"strings"

	csclient "github.com/xenov-x/csrest"
)

// Validator validates workflows before execution
type Validator struct {
	client *csclient.Client
}

// NewValidator creates a new workflow validator
func NewValidator(client *csclient.Client) *Validator {
	return &Validator{client: client}
}

// Validate performs pre-flight validation of a workflow
func (v *Validator) Validate(ctx context.Context, wf *Workflow) []ValidationError {
	var errors []ValidationError

	// Validate workflow name
	if wf.Name == "" {
		errors = append(errors, ValidationError{
			Type:    "workflow",
			Message: "workflow name is required",
		})
	}

	// Validate variables
	varErrors := v.validateVariables(wf)
	errors = append(errors, varErrors...)

	// Validate beacon ID if specified
	if wf.BeaconID != "" && v.client != nil {
		beacon, err := v.client.GetBeacon(ctx, wf.BeaconID)
		if err != nil {
			errors = append(errors, ValidationError{
				Type:    "beacon",
				Message: fmt.Sprintf("invalid beacon_id '%s': %v", wf.BeaconID, err),
			})
		} else if !beacon.Alive {
			errors = append(errors, ValidationError{
				Type:     "beacon",
				Message:  fmt.Sprintf("beacon '%s' is not alive", wf.BeaconID),
				Severity: "warning",
			})
		}
	}

	// Validate actions
	if len(wf.Actions) == 0 {
		errors = append(errors, ValidationError{
			Type:    "actions",
			Message: "workflow must have at least one action",
		})
	}

	actionNames := make(map[string]bool)
	for i, action := range wf.Actions {
		actionErrors := v.validateAction(action, i, actionNames)
		errors = append(errors, actionErrors...)
	}

	return errors
}

// validateVariables checks for valid variable names and potential conflicts
func (v *Validator) validateVariables(wf *Workflow) []ValidationError {
	var errors []ValidationError

	for varName := range wf.Variables {
		// Check for reserved prefixes
		if strings.HasPrefix(varName, "beacon.") {
			errors = append(errors, ValidationError{
				Type:     "variable",
				Message:  fmt.Sprintf("variable name '%s' conflicts with reserved 'beacon.' prefix", varName),
				Severity: "warning",
			})
		}

		// Check for empty variable names
		if strings.TrimSpace(varName) == "" {
			errors = append(errors, ValidationError{
				Type:    "variable",
				Message: "variable name cannot be empty",
			})
		}
	}

	return errors
}

// validateAction validates a single action
func (v *Validator) validateAction(action Action, index int, seenNames map[string]bool) []ValidationError {
	var errors []ValidationError
	prefix := fmt.Sprintf("action[%d]", index)

	// Validate name
	if action.Name == "" {
		errors = append(errors, ValidationError{
			Type:    prefix,
			Message: "action name is required",
		})
	} else {
		if seenNames[action.Name] {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: fmt.Sprintf("duplicate action name '%s'", action.Name),
			})
		}
		seenNames[action.Name] = true
	}

	// Validate type
	validTypes := map[string]bool{
		"getuid":          true,
		"getsystem":       true,
		"bof_string":      true,
		"bof_packed":      true,
		"bof_pack":        true,
		"bof_pack_custom": true,
		"sleep":           true,
		"shell":           true,
		"powershell":      true,
		"upload":          true,
		"download":        true,
		"screenshot":      true,
		"consolecommand":  true,
	}

	if !validTypes[action.Type] {
		errors = append(errors, ValidationError{
			Type:    prefix,
			Message: fmt.Sprintf("invalid action type '%s'", action.Type),
		})
	}

	// Validate BOF actions
	if strings.HasPrefix(action.Type, "bof_") {
		bofErrors := v.validateBOFAction(action, prefix)
		errors = append(errors, bofErrors...)
	}

	// Validate sleep action
	if action.Type == "sleep" {
		if action.Parameters == nil || action.Parameters["duration"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "sleep action requires 'duration' parameter",
			})
		}
	}

	// Validate shell action
	if action.Type == "shell" {
		if action.Parameters == nil || action.Parameters["command"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "shell action requires 'command' parameter",
			})
		}
	}

	// Validate powershell action
	if action.Type == "powershell" {
		if action.Parameters == nil || action.Parameters["command"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "powershell action requires 'command' parameter",
			})
		}
	}

	// Validate upload action
	if action.Type == "upload" {
		if action.Parameters == nil || action.Parameters["local_path"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "upload action requires 'local_path' parameter",
			})
		}
	}

	// Validate download action
	if action.Type == "download" {
		if action.Parameters == nil || action.Parameters["remote_path"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "download action requires 'remote_path' parameter",
			})
		}
	}

	// Validate consolecommand action
	if action.Type == "consolecommand" {
		if action.Parameters == nil || action.Parameters["command"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "consolecommand action requires 'command' parameter",
			})
		}
	}

	// Validate condition groups (any_of, all_of)
	for j, cond := range action.AnyOf {
		condErrors := v.validateCondition(cond, fmt.Sprintf("%s.any_of[%d]", prefix, j), seenNames)
		errors = append(errors, condErrors...)
	}

	for j, cond := range action.AllOf {
		condErrors := v.validateCondition(cond, fmt.Sprintf("%s.all_of[%d]", prefix, j), seenNames)
		errors = append(errors, condErrors...)
	}

	// Validate legacy conditions (backward compatibility)
	for j, cond := range action.Conditions {
		condErrors := v.validateCondition(cond, fmt.Sprintf("%s.conditions[%d]", prefix, j), seenNames)
		errors = append(errors, condErrors...)
	}

	// Validate nested actions
	for j, nested := range action.OnSuccess {
		nestedErrors := v.validateAction(nested, j, seenNames)
		for k := range nestedErrors {
			nestedErrors[k].Type = fmt.Sprintf("%s.on_success[%d]", prefix, j)
		}
		errors = append(errors, nestedErrors...)
	}

	for j, nested := range action.OnFailure {
		nestedErrors := v.validateAction(nested, j, seenNames)
		for k := range nestedErrors {
			nestedErrors[k].Type = fmt.Sprintf("%s.on_failure[%d]", prefix, j)
		}
		errors = append(errors, nestedErrors...)
	}

	return errors
}

// validateBOFAction validates BOF-specific parameters
func (v *Validator) validateBOFAction(action Action, prefix string) []ValidationError {
	var errors []ValidationError

	if action.Parameters == nil {
		errors = append(errors, ValidationError{
			Type:    prefix,
			Message: "BOF action requires parameters",
		})
		return errors
	}

	bofPath, ok := action.Parameters["bof"].(string)
	if !ok || bofPath == "" {
		errors = append(errors, ValidationError{
			Type:    prefix,
			Message: "BOF action requires 'bof' parameter",
		})
		return errors
	}

	// Check if BOF file exists (if not using @files/ prefix , or variable interpolation)
	switch {
	case strings.HasPrefix(bofPath, "@files/") || strings.HasPrefix(bofPath, "@artifacts/"): //remote path check
		errors = append(errors, ValidationError{
			Type:     prefix,
			Message:  fmt.Sprintf("BOF file path check skipped due to remote path: %s", bofPath),
			Severity: "warning",
		})
	case strings.Contains(bofPath, "${") && strings.Contains(bofPath, "}"): // Variable check
		errors = append(errors, ValidationError{
			Type:     prefix,
			Message:  fmt.Sprintf("BOF file path check skipped due to runtime variable interpolation: %s", bofPath),
			Severity: "warning",
		})
	default:
		if _, err := os.Stat(bofPath); os.IsNotExist(err) {
			errors = append(errors, ValidationError{
				Type:     prefix,
				Message:  fmt.Sprintf("BOF file not found: %s", bofPath),
				Severity: "warning",
			})
		}
	}

	return errors
}

// validateCondition validates a condition
func (v *Validator) validateCondition(cond Condition, prefix string, seenNames map[string]bool) []ValidationError {
	var errors []ValidationError

	// Check for nested condition groups
	if len(cond.AnyOf) > 0 {
		for j, nestedCond := range cond.AnyOf {
			nestedErrors := v.validateCondition(nestedCond, fmt.Sprintf("%s.any_of[%d]", prefix, j), seenNames)
			errors = append(errors, nestedErrors...)
		}
		return errors
	}

	if len(cond.AllOf) > 0 {
		for j, nestedCond := range cond.AllOf {
			nestedErrors := v.validateCondition(nestedCond, fmt.Sprintf("%s.all_of[%d]", prefix, j), seenNames)
			errors = append(errors, nestedErrors...)
		}
		return errors
	}

	// Validate leaf condition (must have source, operator, value)
	if cond.Source == "" {
		errors = append(errors, ValidationError{
			Type:    prefix,
			Message: "condition source is required",
		})
	} else if strings.HasPrefix(cond.Source, "beacon.") {
		// Validate beacon field reference
		field := strings.TrimPrefix(cond.Source, "beacon.")
		validBeaconFields := map[string]bool{
			"user":         true,
			"computer":     true,
			"internal":     true,
			"external":     true,
			"os":           true,
			"process":      true,
			"pid":          true,
			"isAdmin":      true,
			"beaconArch":   true,
			"systemArch":   true,
			"session":      true,
			"listener":     true,
			"alive":        true,
			"impersonated": true,
		}
		if !validBeaconFields[field] {
			errors = append(errors, ValidationError{
				Type:     prefix,
				Message:  fmt.Sprintf("unknown beacon field '%s'", field),
				Severity: "warning",
			})
		}
	} else if !seenNames[cond.Source] {
		// Regular action reference
		errors = append(errors, ValidationError{
			Type:     prefix,
			Message:  fmt.Sprintf("condition references undefined action '%s'", cond.Source),
			Severity: "warning",
		})
	}

	// Validate operator
	validOperators := map[string]bool{
		"contains":     true,
		"not_contains": true,
		"equals":       true,
		"matches":      true,
	}

	if !validOperators[cond.Operator] {
		errors = append(errors, ValidationError{
			Type:    prefix,
			Message: fmt.Sprintf("invalid operator '%s'", cond.Operator),
		})
	}

	// Validate value
	if cond.Value == "" {
		errors = append(errors, ValidationError{
			Type:    prefix,
			Message: "condition value is required",
		})
	}

	return errors
}

// ValidationError represents a workflow validation error
type ValidationError struct {
	Type     string
	Message  string
	Severity string // "", "warning"
}

func (e ValidationError) String() string {
	severity := "ERROR"
	if e.Severity == "warning" {
		severity = "WARNING"
	}
	return fmt.Sprintf("[%s] %s: %s", severity, e.Type, e.Message)
}
