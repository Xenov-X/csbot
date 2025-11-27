package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Format represents an output format type
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

// Result represents a workflow execution result
type Result struct {
	WorkflowName string                 `json:"workflow_name"`
	BeaconID     string                 `json:"beacon_id"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      time.Time              `json:"end_time"`
	Duration     time.Duration          `json:"duration"`
	Success      bool                   `json:"success"`
	Error        string                 `json:"error,omitempty"`
	Actions      []ActionResult         `json:"actions"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ActionResult represents a single action result
type ActionResult struct {
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	Success   bool          `json:"success"`
	Output    string        `json:"output,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// Formatter handles output formatting
type Formatter struct {
	format Format
	writer io.Writer
}

// NewFormatter creates a new output formatter
func NewFormatter(format Format, writer io.Writer) *Formatter {
	if writer == nil {
		writer = os.Stdout
	}
	return &Formatter{
		format: format,
		writer: writer,
	}
}

// WriteResult writes a result in the configured format
func (f *Formatter) WriteResult(result *Result) error {
	switch f.format {
	case FormatJSON:
		return f.writeJSON(result)
	case FormatCSV:
		return f.writeCSV(result)
	case FormatText:
		return f.writeText(result)
	default:
		return fmt.Errorf("unsupported format: %s", f.format)
	}
}

// writeJSON writes result as JSON
func (f *Formatter) writeJSON(result *Result) error {
	encoder := json.NewEncoder(f.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// writeCSV writes result as CSV
func (f *Formatter) writeCSV(result *Result) error {
	w := csv.NewWriter(f.writer)
	defer w.Flush()

	// Header
	if err := w.Write([]string{
		"Action", "Type", "StartTime", "EndTime", "Duration(s)", "Success", "Output", "Error",
	}); err != nil {
		return err
	}

	// Rows
	for _, action := range result.Actions {
		successStr := "false"
		if action.Success {
			successStr = "true"
		}

		if err := w.Write([]string{
			action.Name,
			action.Type,
			action.StartTime.Format(time.RFC3339),
			action.EndTime.Format(time.RFC3339),
			fmt.Sprintf("%.2f", action.Duration.Seconds()),
			successStr,
			action.Output,
			action.Error,
		}); err != nil {
			return err
		}
	}

	return nil
}

// writeText writes result as human-readable text
func (f *Formatter) writeText(result *Result) error {
	fmt.Fprintf(f.writer, "\n=== Workflow Execution Summary ===\n")
	fmt.Fprintf(f.writer, "Workflow: %s\n", result.WorkflowName)
	fmt.Fprintf(f.writer, "Beacon ID: %s\n", result.BeaconID)
	fmt.Fprintf(f.writer, "Start Time: %s\n", result.StartTime.Format(time.RFC3339))
	fmt.Fprintf(f.writer, "End Time: %s\n", result.EndTime.Format(time.RFC3339))
	fmt.Fprintf(f.writer, "Duration: %s\n", result.Duration)

	statusSymbol := "✓"
	statusText := "SUCCESS"
	if !result.Success {
		statusSymbol = "✗"
		statusText = "FAILED"
	}
	fmt.Fprintf(f.writer, "Status: %s %s\n", statusSymbol, statusText)

	if result.Error != "" {
		fmt.Fprintf(f.writer, "Error: %s\n", result.Error)
	}

	fmt.Fprintf(f.writer, "\n=== Actions (%d total) ===\n", len(result.Actions))
	for i, action := range result.Actions {
		fmt.Fprintf(f.writer, "\n[%d] %s (%s)\n", i+1, action.Name, action.Type)
		fmt.Fprintf(f.writer, "    Duration: %s\n", action.Duration)

		if action.Success {
			fmt.Fprintf(f.writer, "    Status: ✓ Success\n")
			if action.Output != "" {
				fmt.Fprintf(f.writer, "    Output: %s\n", action.Output)
			}
		} else {
			fmt.Fprintf(f.writer, "    Status: ✗ Failed\n")
			if action.Error != "" {
				fmt.Fprintf(f.writer, "    Error: %s\n", action.Error)
			}
		}
	}

	fmt.Fprintf(f.writer, "\n")
	return nil
}

// // truncateOutput truncates output to maxLen characters
// func truncateOutput(s string, maxLen int) string {
// 	if len(s) <= maxLen {
// 		return s
// 	}
// 	return s[:maxLen] + "... (truncated)"
// }
