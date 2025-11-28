package workflow

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xenov-x/csbot/logger"
	csclient "github.com/xenov-x/csrest"
)

// Executor executes workflows
type Executor struct {
	host        string
	port        int
	httpClient  *http.Client
	beacon      *csclient.BeaconDto // beacon metadata for condition evaluation
	outputs     map[string]string   // stores outputs from previous actions and beacon metadata
	outputMu    sync.RWMutex        // protects outputs map for concurrent access
	logger      *logger.Logger
	taskTimeout time.Duration
	results     []ActionResult // stores action results for output formatting
	resultsMu   sync.Mutex     // protects results slice
}

// ActionResult represents the result of an action execution
type ActionResult struct {
	Name      string
	Type      string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Success   bool
	Output    string
	Error     string
}

// NewExecutor creates a new workflow executor
func NewExecutor(host string, port int, httpClient *http.Client) *Executor {
	return &Executor{
		host:        host,
		port:        port,
		httpClient:  httpClient,
		outputs:     make(map[string]string),
		taskTimeout: 5 * time.Minute, // default
	}
}

// SetLogger sets the logger for the executor
func (e *Executor) SetLogger(log *logger.Logger) {
	e.logger = log
}

// SetTaskTimeout sets the timeout for task completion
func (e *Executor) SetTaskTimeout(timeout time.Duration) {
	e.taskTimeout = timeout
}

// GetResults returns the action results
func (e *Executor) GetResults() []ActionResult {
	e.resultsMu.Lock()
	defer e.resultsMu.Unlock()
	return e.results
}

// recordResult records an action result
func (e *Executor) recordResult(result ActionResult) {
	e.resultsMu.Lock()
	e.results = append(e.results, result)
	e.resultsMu.Unlock()
}

// logInfo logs an info message
func (e *Executor) logInfo(format string, args ...interface{}) {
	if e.logger != nil {
		e.logger.Info(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// logError logs an error message
func (e *Executor) logError(format string, args ...interface{}) {
	if e.logger != nil {
		e.logger.Error(format, args...)
	} else {
		log.Printf("ERROR: "+format, args...)
	}
}

// logDebug logs a debug message
func (e *Executor) logDebug(format string, args ...interface{}) {
	if e.logger != nil {
		e.logger.Debug(format, args...)
	} else {
		log.Printf("DEBUG: "+format, args...)
	}
}

// Execute runs a workflow
func (e *Executor) Execute(ctx context.Context, wf *Workflow, username, password string) error {
	// Create client
	client := csclient.NewClient(e.host, e.port)
	client.SetHTTPClient(e.httpClient)

	// Authenticate
	e.logInfo("Authenticating as %s...", username)
	_, err := client.Login(ctx, username, password, 3600000) // 1 hour
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	e.logInfo("Authentication successful")

	// Fetch beacon metadata
	e.logInfo("Fetching beacon metadata for %s...", wf.BeaconID)
	beacon, err := client.GetBeacon(ctx, wf.BeaconID)
	if err != nil {
		return fmt.Errorf("failed to fetch beacon metadata: %w", err)
	}
	e.beacon = beacon
	e.storeBeaconMetadata()
	e.storeWorkflowVariables(wf.Variables)

	// Execute workflow
	e.logInfo("Starting workflow: %s", wf.Name)
	e.logInfo("Target beacon: %s", wf.BeaconID)

	if wf.Parallel {
		e.logInfo("Parallel execution enabled")
		return e.executeActionsParallel(ctx, client, wf.BeaconID, wf.Actions)
	}

	return e.executeActions(ctx, client, wf.BeaconID, wf.Actions)
}

// executeActionsParallel executes actions in parallel
func (e *Executor) executeActionsParallel(ctx context.Context, client *csclient.Client, beaconID string, actions []Action) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(actions))

	for i, action := range actions {
		// Check conditions before starting goroutine
		if !e.evaluateActionConditions(action) {
			e.logInfo("[%d] Conditions not met, skipping action: %s", i+1, action.Name)
			continue
		}

		wg.Add(1)
		go func(idx int, act Action) {
			defer wg.Done()

			e.logInfo("[%d] Executing action: %s (type: %s)", idx+1, act.Name, act.Type)

			output, err := e.executeAction(ctx, client, beaconID, act)
			if err != nil {
				e.logError("[%d] Action failed: %v", idx+1, err)

				// Execute on_failure actions
				if len(act.OnFailure) > 0 {
					e.logInfo("[%d] Executing on_failure actions", idx+1)
					if failErr := e.executeActions(ctx, client, beaconID, act.OnFailure); failErr != nil {
						errCh <- failErr
						return
					}
				}

				errCh <- fmt.Errorf("action %s failed: %w", act.Name, err)
				return
			}

			// Store output (thread-safe)
			e.outputMu.Lock()
			e.outputs[act.Name] = output
			e.outputMu.Unlock()

			e.logInfo("[%d] Action completed successfully", idx+1)

			// Execute on_success actions
			if len(act.OnSuccess) > 0 {
				e.logInfo("[%d] Executing on_success actions", idx+1)
				if succErr := e.executeActions(ctx, client, beaconID, act.OnSuccess); succErr != nil {
					errCh <- succErr
				}
			}
		}(i, action)
	}

	wg.Wait()
	close(errCh)

	// Check for errors
	for err := range errCh {
		return err
	}

	return nil
}

// executeActions executes a list of actions
func (e *Executor) executeActions(ctx context.Context, client *csclient.Client, beaconID string, actions []Action) error {
	for i, action := range actions {
		e.logInfo("[%d] Executing action: %s (type: %s)", i+1, action.Name, action.Type)

		startTime := time.Now()
		result := ActionResult{
			Name:      action.Name,
			Type:      action.Type,
			StartTime: startTime,
		}

		// Check conditions
		if !e.evaluateActionConditions(action) {
			e.logInfo("[%d] Conditions not met, skipping action", i+1)
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)
			result.Success = true
			result.Output = "Skipped (conditions not met)"
			e.recordResult(result)
			continue
		}

		// Execute action
		output, err := e.executeAction(ctx, client, beaconID, action)
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)

		if err != nil {
			e.logError("[%d] Action failed: %v", i+1, err)
			result.Success = false
			result.Error = err.Error()
			e.recordResult(result)

			// Execute on_failure actions
			if len(action.OnFailure) > 0 {
				e.logInfo("[%d] Executing on_failure actions", i+1)
				if err := e.executeActions(ctx, client, beaconID, action.OnFailure); err != nil {
					return err
				}
			}

			return fmt.Errorf("action %s failed: %w", action.Name, err)
		}

		// Store output
		e.outputs[action.Name] = output
		result.Success = true
		result.Output = output
		e.recordResult(result)

		e.logInfo("[%d] Action completed successfully", i+1)

		// Execute on_success actions
		if len(action.OnSuccess) > 0 {
			e.logInfo("[%d] Executing on_success actions", i+1)
			if err := e.executeActions(ctx, client, beaconID, action.OnSuccess); err != nil {
				return err
			}
		}
	}

	return nil
}

// executeAction executes a single action
func (e *Executor) executeAction(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	// Interpolate variables in parameters before execution
	action = e.interpolateAction(action)

	switch action.Type {
	case "bof_string":
		return e.executeBOFString(ctx, client, beaconID, action)
	case "bof_packed":
		return e.executeBOFPacked(ctx, client, beaconID, action)
	case "bof_pack":
		return e.executeBOFPack(ctx, client, beaconID, action)
	case "bof_pack_custom":
		return e.executeBOFPackCustom(ctx, client, beaconID, action)
	case "getuid":
		return e.executeGetUID(ctx, client, beaconID)
	case "getsystem":
		return e.executeGetSystem(ctx, client, beaconID)
	case "sleep":
		return e.executeSleep(action)
	case "shell":
		return e.executeShell(ctx, client, beaconID, action)
	case "powershell":
		return e.executePowerShell(ctx, client, beaconID, action)
	case "upload":
		return e.executeUpload(ctx, client, beaconID, action)
	case "download":
		return e.executeDownload(ctx, client, beaconID, action)
	case "screenshot":
		return e.executeScreenshot(ctx, client, beaconID)
	case "consolecommand":
		return e.executeConsoleCommand(ctx, client, beaconID, action)
	default:
		return "", fmt.Errorf("unknown action type: %s", action.Type)
	}
}

// interpolateAction replaces ${action_name} variables with action outputs
func (e *Executor) interpolateAction(action Action) Action {
	e.outputMu.RLock()
	defer e.outputMu.RUnlock()

	// Create a copy of the action to avoid modifying the original
	interpolated := action
	interpolated.Parameters = make(map[string]interface{})

	for key, value := range action.Parameters {
		if strVal, ok := value.(string); ok {
			// Replace ${action_name} with output from that action
			interpolated.Parameters[key] = e.interpolateString(strVal)
		} else {
			interpolated.Parameters[key] = value
		}
	}

	return interpolated
}

// interpolateString replaces ${action_name} variables with outputs
func (e *Executor) interpolateString(s string) string {
	result := s

	// Find all ${...} patterns
	for actionName, output := range e.outputs {
		placeholder := fmt.Sprintf("${%s}", actionName)
		result = strings.ReplaceAll(result, placeholder, output)
	}

	return result
}

// executeBOFString executes a BOF with string arguments
func (e *Executor) executeBOFString(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	bofPath, ok := action.Parameters["bof"].(string)
	if !ok {
		return "", fmt.Errorf("bof parameter required")
	}

	// Read BOF file
	bofData, err := os.ReadFile(bofPath)
	if err != nil {
		return "", fmt.Errorf("failed to read BOF file: %w", err)
	}

	bofBase64 := base64.StdEncoding.EncodeToString(bofData)

	req := csclient.InlineExecuteStringDto{
		BOF:   "@files/bof.o",
		Files: map[string]string{"bof.o": bofBase64},
	}

	if ep, ok := action.Parameters["entrypoint"].(string); ok {
		req.Entrypoint = ep
	}
	if args, ok := action.Parameters["arguments"].(string); ok {
		req.Arguments = args
	}

	resp, err := client.ExecuteBOFString(ctx, beaconID, req)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeBOFPacked executes a BOF with packed arguments
func (e *Executor) executeBOFPacked(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	bofPath, ok := action.Parameters["bof"].(string)
	if !ok {
		return "", fmt.Errorf("bof parameter required")
	}

	bofData, err := os.ReadFile(bofPath)
	if err != nil {
		return "", fmt.Errorf("failed to read BOF file: %w", err)
	}

	bofBase64 := base64.StdEncoding.EncodeToString(bofData)

	req := csclient.InlineExecutePackedDto{
		BOF:   "@files/bof.o",
		Files: map[string]string{"bof.o": bofBase64},
	}

	if ep, ok := action.Parameters["entrypoint"].(string); ok {
		req.Entrypoint = ep
	}
	if args, ok := action.Parameters["arguments"].(string); ok {
		req.Arguments = args
	}

	resp, err := client.ExecuteBOFPacked(ctx, beaconID, req)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeBOFPack executes a BOF with typed arguments
func (e *Executor) executeBOFPack(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	bofPath, ok := action.Parameters["bof"].(string)
	if !ok {
		return "", fmt.Errorf("bof parameter required")
	}

	bofData, err := os.ReadFile(bofPath)
	if err != nil {
		return "", fmt.Errorf("failed to read BOF file: %w", err)
	}

	bofBase64 := base64.StdEncoding.EncodeToString(bofData)

	req := csclient.InlineExecutePackDto{
		BOF:   "@files/bof.o",
		Files: map[string]string{"bof.o": bofBase64},
	}

	if ep, ok := action.Parameters["entrypoint"].(string); ok {
		req.Entrypoint = ep
	}

	// Parse arguments
	if argsInterface, ok := action.Parameters["arguments"].([]interface{}); ok {
		var args []csclient.BOFArgument
		for _, arg := range argsInterface {
			argMap, ok := arg.(map[string]interface{})
			if !ok {
				continue
			}

			argType, _ := argMap["type"].(string)
			switch argType {
			case "string":
				args = append(args, csclient.StringArg{
					Type:  "string",
					Value: argMap["value"].(string),
				})
			case "wstring":
				args = append(args, csclient.WStringArg{
					Type:  "wstring",
					Value: argMap["value"].(string),
				})
			case "int":
				args = append(args, csclient.IntArg{
					Type:  "int",
					Value: int(argMap["value"].(float64)),
				})
			case "short":
				args = append(args, csclient.ShortArg{
					Type:  "short",
					Value: int(argMap["value"].(float64)),
				})
			}
		}
		req.Arguments = args
	}

	resp, err := client.ExecuteBOFPack(ctx, beaconID, req)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeGetUID executes getuid command
func (e *Executor) executeGetUID(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.GetUID(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeGetSystem executes getsystem command
func (e *Executor) executeGetSystem(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.GetSystem(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSleep pauses execution
func (e *Executor) executeSleep(action Action) (string, error) {
	duration, ok := action.Parameters["duration"].(string)
	if !ok {
		return "", fmt.Errorf("duration parameter required for sleep")
	}

	d, err := time.ParseDuration(duration)
	if err != nil {
		return "", fmt.Errorf("invalid duration: %w", err)
	}

	e.logInfo("Sleeping for %s", d)
	time.Sleep(d)
	return "slept", nil
}

// waitForOutput waits for task output
func (e *Executor) waitForOutput(ctx context.Context, client *csclient.Client, taskID string) (string, error) {
	e.logDebug("Waiting for task output (taskID: %s, timeout: %s)", taskID, e.taskTimeout)

	task, err := client.WaitForTaskCompletion(ctx, taskID, e.taskTimeout)
	if err != nil {
		return "", fmt.Errorf("failed to get task output: %w", err)
	}

	// Extract text output from result
	var output strings.Builder
	for _, result := range task.Result {
		if text, ok := result["output"].(string); ok {
			output.WriteString(text)
		}
		if text, ok := result["text"].(string); ok {
			output.WriteString(text)
		}
	}

	outputStr := output.String()
	if outputStr != "" {
		e.logDebug("Task output received (%d bytes)", len(outputStr))
	} else {
		e.logDebug("Task completed with no output")
	}

	return outputStr, nil
}

// evaluateActionConditions evaluates all condition groups for an action
func (e *Executor) evaluateActionConditions(action Action) bool {
	// If using new any_of or all_of fields
	if len(action.AnyOf) > 0 {
		e.logDebug("Evaluating any_of conditions for action: %s", action.Name)
		result := e.checkAnyOf(action.AnyOf)
		e.logDebug("AnyOf result: %v", result)
		return result
	}
	if len(action.AllOf) > 0 {
		e.logDebug("Evaluating all_of conditions for action: %s", action.Name)
		result := e.checkAllOf(action.AllOf)
		e.logDebug("AllOf result: %v", result)
		return result
	}
	// Fall back to legacy conditions field (all must be true)
	if len(action.Conditions) > 0 {
		e.logDebug("Evaluating legacy conditions for action: %s", action.Name)
		result := e.checkAllOf(action.Conditions)
		e.logDebug("Conditions result: %v", result)
		return result
	}
	return true
}

// checkAnyOf checks if at least one condition is true (OR logic)
func (e *Executor) checkAnyOf(conditions []Condition) bool {
	if len(conditions) == 0 {
		return true
	}

	for i, cond := range conditions {
		e.logDebug("  Checking any_of condition %d: source=%s, operator=%s, value=%s", i+1, cond.Source, cond.Operator, cond.Value)
		if e.evaluateCondition(cond) {
			e.logDebug("  Condition %d matched!", i+1)
			return true
		}
		e.logDebug("  Condition %d did not match", i+1)
	}

	e.logDebug("AnyOf: No conditions met")
	return false
}

// checkAllOf checks if all conditions are true (AND logic)
func (e *Executor) checkAllOf(conditions []Condition) bool {
	if len(conditions) == 0 {
		return true
	}

	for _, cond := range conditions {
		if !e.evaluateCondition(cond) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single condition (supports nested any_of/all_of)
func (e *Executor) evaluateCondition(cond Condition) bool {
	// Check for nested condition groups
	if len(cond.AnyOf) > 0 {
		return e.checkAnyOf(cond.AnyOf)
	}
	if len(cond.AllOf) > 0 {
		return e.checkAllOf(cond.AllOf)
	}

	// Evaluate leaf condition
	return e.checkCondition(cond)
}

// checkConditions checks if all conditions are met (legacy - kept for backward compatibility)
func (e *Executor) checkConditions(conditions []Condition) bool {
	return e.checkAllOf(conditions)
}

// checkCondition checks a single condition
func (e *Executor) checkCondition(cond Condition) bool {
	e.outputMu.RLock()
	output, exists := e.outputs[cond.Source]
	e.outputMu.RUnlock()

	if !exists {
		e.logDebug("    Source '%s' not found in outputs", cond.Source)
		return false
	}

	e.logDebug("    Source '%s' = '%s'", cond.Source, output)

	// Prepare strings for comparison
	compareOutput := output
	compareValue := cond.Value
	if !cond.CaseSensitive {
		compareOutput = strings.ToLower(output)
		compareValue = strings.ToLower(cond.Value)
	}

	switch cond.Operator {
	case "contains":
		result := strings.Contains(compareOutput, compareValue)
		e.logDebug("Condition check: '%s' contains '%s' = %v", cond.Source, cond.Value, result)
		return result

	case "not_contains":
		result := !strings.Contains(compareOutput, compareValue)
		e.logDebug("Condition check: '%s' not contains '%s' = %v", cond.Source, cond.Value, result)
		return result

	case "equals":
		result := compareOutput == compareValue
		e.logDebug("Condition check: '%s' equals '%s' = %v", cond.Source, cond.Value, result)
		return result

	case "matches":
		re, err := regexp.Compile(cond.Value)
		if err != nil {
			e.logError("Condition check: invalid regex '%s': %v", cond.Value, err)
			return false
		}
		result := re.MatchString(output)
		e.logDebug("Condition check: '%s' matches '%s' = %v", cond.Source, cond.Value, result)
		return result

	default:
		e.logError("Condition check: unknown operator '%s'", cond.Operator)
		return false
	}
}

// executeShell executes a shell command
func (e *Executor) executeShell(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	command, ok := action.Parameters["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required for shell")
	}

	resp, err := client.ExecuteShell(ctx, beaconID, command)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executePowerShell executes a PowerShell command
func (e *Executor) executePowerShell(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	command, ok := action.Parameters["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required for powershell")
	}

	resp, err := client.ExecutePowerShell(ctx, beaconID, command)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeUpload uploads a file to the beacon's current working directory
func (e *Executor) executeUpload(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	localPath, ok := action.Parameters["local_path"].(string)
	if !ok {
		return "", fmt.Errorf("local_path parameter required for upload")
	}

	resp, err := client.Upload(ctx, beaconID, localPath)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeDownload downloads a file from the beacon
func (e *Executor) executeDownload(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	remotePath, ok := action.Parameters["remote_path"].(string)
	if !ok {
		return "", fmt.Errorf("remote_path parameter required for download")
	}

	resp, err := client.Download(ctx, beaconID, remotePath)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeBOFPackCustom executes a BOF with custom packed arguments
func (e *Executor) executeBOFPackCustom(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	bofPath, ok := action.Parameters["bof"].(string)
	if !ok {
		return "", fmt.Errorf("bof parameter required")
	}

	bofData, err := os.ReadFile(bofPath)
	if err != nil {
		return "", fmt.Errorf("failed to read BOF file: %w", err)
	}

	bofBase64 := base64.StdEncoding.EncodeToString(bofData)

	// Parse arguments array
	var packedArgs []byte
	if argsInterface, ok := action.Parameters["arguments"].([]interface{}); ok {
		var bofArgs []BOFArgument
		for _, arg := range argsInterface {
			argMap, ok := arg.(map[string]interface{})
			if !ok {
				continue
			}

			argType, _ := argMap["type"].(string)
			bofArg := BOFArgument{
				Type:  argType,
				Value: argMap["value"],
			}
			bofArgs = append(bofArgs, bofArg)
		}

		// Pack arguments using custom packer
		packedArgs, err = PackBOFArguments(bofArgs)
		if err != nil {
			return "", fmt.Errorf("failed to pack arguments: %w", err)
		}
	}

	// Encode packed arguments as base64 string
	packedArgsBase64 := base64.StdEncoding.EncodeToString(packedArgs)

	req := csclient.InlineExecutePackedDto{
		BOF:       "@files/bof.o",
		Files:     map[string]string{"bof.o": bofBase64},
		Arguments: packedArgsBase64,
	}

	if ep, ok := action.Parameters["entrypoint"].(string); ok {
		req.Entrypoint = ep
	}

	resp, err := client.ExecuteBOFPacked(ctx, beaconID, req)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeScreenshot captures a screenshot
func (e *Executor) executeScreenshot(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	// Use spawn method by default (simpler, no PID/arch required)
	resp, err := client.ScreenshotSpawn(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeConsoleCommand executes a console command on the beacon
func (e *Executor) executeConsoleCommand(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	command, ok := action.Parameters["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required for consolecommand")
	}

	cmd := csclient.CommandDto{
		Command: command,
	}

	// Add optional arguments
	if args, ok := action.Parameters["arguments"].(string); ok {
		cmd.Arguments = args
	}

	// Add optional files map for @files/ references
	if filesInterface, ok := action.Parameters["files"].(map[string]interface{}); ok {
		cmd.Files = make(map[string]string)
		for key, value := range filesInterface {
			if strVal, ok := value.(string); ok {
				cmd.Files[key] = strVal
			}
		}
	}

	resp, err := client.ExecuteConsoleCommand(ctx, beaconID, cmd)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// storeBeaconMetadata stores beacon metadata in outputs map for condition evaluation
func (e *Executor) storeBeaconMetadata() {
	if e.beacon == nil {
		return
	}

	e.outputMu.Lock()
	defer e.outputMu.Unlock()

	// Store commonly used beacon fields with beacon. prefix
	e.outputs["beacon.user"] = e.beacon.User
	e.outputs["beacon.computer"] = e.beacon.Computer
	e.outputs["beacon.internal"] = e.beacon.Internal
	e.outputs["beacon.external"] = e.beacon.External
	e.outputs["beacon.os"] = e.beacon.OS
	e.outputs["beacon.process"] = e.beacon.Process
	e.outputs["beacon.pid"] = fmt.Sprintf("%d", e.beacon.PID)
	e.outputs["beacon.isAdmin"] = fmt.Sprintf("%t", e.beacon.IsAdmin)
	e.outputs["beacon.beaconArch"] = e.beacon.BeaconArch
	e.outputs["beacon.systemArch"] = e.beacon.SystemArch
	e.outputs["beacon.session"] = e.beacon.Session
	e.outputs["beacon.listener"] = e.beacon.Listener
	e.outputs["beacon.alive"] = fmt.Sprintf("%t", e.beacon.Alive)

	if e.beacon.Impersonated != "" {
		e.outputs["beacon.impersonated"] = e.beacon.Impersonated
	}

	e.logDebug("Stored beacon metadata for conditions: user=%s, isAdmin=%t, os=%s",
		e.beacon.User, e.beacon.IsAdmin, e.beacon.OS)
}

// storeWorkflowVariables stores user-defined variables in outputs map for interpolation
func (e *Executor) storeWorkflowVariables(variables map[string]string) {
	if len(variables) == 0 {
		return
	}

	e.outputMu.Lock()
	defer e.outputMu.Unlock()

	for name, value := range variables {
		e.outputs[name] = value
		e.logDebug("Stored workflow variable: %s = %s", name, value)
	}

	e.logInfo("Loaded %d workflow variable(s)", len(variables))
}
