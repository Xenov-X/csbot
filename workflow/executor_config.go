package workflow

import (
	"context"
	"fmt"

	csclient "github.com/xenov-x/csrest"
)

// ============================================================
// Beacon Configuration Action Handlers
// ============================================================

// executeBeaconInfo retrieves beacon metadata and configuration
func (e *Executor) executeBeaconInfo(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.BeaconInfo(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSetSleep sets the beacon's sleep time and jitter
func (e *Executor) executeSetSleep(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	sleepVal, ok := action.Parameters["sleep"]
	if !ok {
		return "", fmt.Errorf("sleep parameter required for set_sleep")
	}

	jitterVal, ok := action.Parameters["jitter"]
	if !ok {
		return "", fmt.Errorf("jitter parameter required for set_sleep")
	}

	var sleep, jitter int
	switch v := sleepVal.(type) {
	case float64:
		sleep = int(v)
	case int:
		sleep = v
	default:
		return "", fmt.Errorf("sleep parameter must be a number")
	}

	switch v := jitterVal.(type) {
	case float64:
		jitter = int(v)
	case int:
		jitter = v
	default:
		return "", fmt.Errorf("jitter parameter must be a number")
	}

	resp, err := client.SetSleepTime(ctx, beaconID, sleep, jitter)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSetNote assigns a note to the beacon
func (e *Executor) executeSetNote(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	note, ok := action.Parameters["note"].(string)
	if !ok {
		return "", fmt.Errorf("note parameter required for set_note")
	}

	resp, err := client.SetNote(ctx, beaconID, note)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeEnableBeaconGate enables beacon gate for the specified beacon
func (e *Executor) executeEnableBeaconGate(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.EnableBeaconGate(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeDisableBeaconGate disables beacon gate for the specified beacon
func (e *Executor) executeDisableBeaconGate(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.DisableBeaconGate(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeEnableBlockDlls enables block DLLs for the specified beacon
func (e *Executor) executeEnableBlockDlls(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.EnableBlockDlls(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeDisableBlockDlls disables block DLLs for the specified beacon
func (e *Executor) executeDisableBlockDlls(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.DisableBlockDlls(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSetSpawnto sets the spawn-to process for the specified beacon
func (e *Executor) executeSetSpawnto(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	arch, ok := action.Parameters["arch"].(string)
	if !ok {
		return "", fmt.Errorf("arch parameter required for set_spawnto")
	}

	path, ok := action.Parameters["path"].(string)
	if !ok {
		return "", fmt.Errorf("path parameter required for set_spawnto")
	}

	resp, err := client.SetSpawnTo(ctx, beaconID, arch, path)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeUnsetSpawnto unsets the spawn-to process for the specified beacon
func (e *Executor) executeUnsetSpawnto(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.UnsetSpawnTo(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSetPpid sets the parent process ID for the specified beacon
func (e *Executor) executeSetPpid(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	ppidVal, ok := action.Parameters["ppid"]
	if !ok {
		return "", fmt.Errorf("ppid parameter required for set_ppid")
	}

	var ppid int
	switch v := ppidVal.(type) {
	case float64:
		ppid = int(v)
	case int:
		ppid = v
	default:
		return "", fmt.Errorf("ppid parameter must be a number")
	}

	resp, err := client.SetPpid(ctx, beaconID, ppid)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeUnsetPpid unsets the parent process ID for the specified beacon
func (e *Executor) executeUnsetPpid(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.UnsetPpid(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSetDnsMode sets the DNS beacon mode (dns, dns6, or dnsTxt)
func (e *Executor) executeSetDnsMode(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	mode, ok := action.Parameters["mode"].(string)
	if !ok {
		return "", fmt.Errorf("mode parameter required for set_dns_mode")
	}

	resp, err := client.SetDnsMode(ctx, beaconID, mode)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSetSyscallMethod sets the syscall method for the beacon
func (e *Executor) executeSetSyscallMethod(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	method, ok := action.Parameters["method"].(string)
	if !ok {
		return "", fmt.Errorf("method parameter required for set_syscall_method")
	}

	resp, err := client.SetSyscallMethod(ctx, beaconID, method)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// ============================================================
// Beacon Management Action Handlers
// ============================================================

// executeDeleteBeacon removes a beacon from the team server
func (e *Executor) executeDeleteBeacon(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	err := client.DeleteBeacon(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Beacon %s deleted", beaconID), nil
}

// executeClearQueue clears the command queue for the specified beacon
func (e *Executor) executeClearQueue(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.ClearCommandQueue(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeCheckin forces a DNS beacon to check in immediately
func (e *Executor) executeCheckin(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.CheckIn(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeConsoleCommand executes a console command on the beacon
func (e *Executor) executeConsoleCommand(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	command, ok := action.Parameters["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required for console_command")
	}

	arguments, _ := action.Parameters["arguments"].(string) // optional

	// Files parameter is optional, parse if present
	var files map[string]string
	if filesInterface, ok := action.Parameters["files"].(map[string]interface{}); ok {
		files = make(map[string]string)
		for k, v := range filesInterface {
			if strVal, ok := v.(string); ok {
				files[k] = strVal
			}
		}
	}

	resp, err := client.ConsoleCommand(ctx, beaconID, command, arguments, files)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeListJobs lists all active jobs for the specified beacon
func (e *Executor) executeListJobs(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.ListJobs(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}
