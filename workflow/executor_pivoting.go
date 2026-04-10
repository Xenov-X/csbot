package workflow

import (
	"context"
	"fmt"

	csclient "github.com/xenov-x/csrest"
)

// --- Pivoting and Lateral Movement Handlers ---

// executeLinkSmb connects to an SMB beacon and re-establishes control
func (e *Executor) executeLinkSmb(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, ok := action.Parameters["target"].(string)
	if !ok {
		return "", fmt.Errorf("target parameter required for link_smb")
	}

	pipe, _ := action.Parameters["pipe"].(string) // optional

	resp, err := client.LinkSmb(ctx, beaconID, target, pipe)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, "link smb "+target)
}

// executeLinkTcp connects to a TCP beacon and re-establishes control
func (e *Executor) executeLinkTcp(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, ok := action.Parameters["target"].(string)
	if !ok {
		return "", fmt.Errorf("target parameter required for link_tcp")
	}

	var port int
	if portVal, ok := action.Parameters["port"]; ok {
		switch v := portVal.(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		default:
			return "", fmt.Errorf("port parameter must be a number")
		}
	}

	resp, err := client.LinkTcp(ctx, beaconID, target, port)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, "link tcp "+target)
}

// executeUnlink disconnects from a named pipe or TCP beacon
func (e *Executor) executeUnlink(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	host, ok := action.Parameters["host"].(string)
	if !ok {
		return "", fmt.Errorf("host parameter required for unlink")
	}

	var pid int
	if pidVal, ok := action.Parameters["pid"]; ok {
		switch v := pidVal.(type) {
		case float64:
			pid = int(v)
		case int:
			pid = v
		default:
			return "", fmt.Errorf("pid parameter must be a number")
		}
	}

	resp, err := client.Unlink(ctx, beaconID, host, pid)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, "unlink "+host)
}

// executeSsh spawns a temporary process to run an SSH client with username/password
func (e *Executor) executeSsh(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, ok := action.Parameters["target"].(string)
	if !ok {
		return "", fmt.Errorf("target parameter required for ssh")
	}

	username, ok := action.Parameters["username"].(string)
	if !ok {
		return "", fmt.Errorf("username parameter required for ssh")
	}

	password, ok := action.Parameters["password"].(string)
	if !ok {
		return "", fmt.Errorf("password parameter required for ssh")
	}

	var port int
	if portVal, ok := action.Parameters["port"]; ok {
		switch v := portVal.(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		default:
			return "", fmt.Errorf("port parameter must be a number")
		}
	} else {
		port = 22 // default SSH port
	}

	resp, err := client.SpawnSsh(ctx, beaconID, target, port, username, password)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeSshKey spawns a temporary process to run an SSH client with SSH key authentication
func (e *Executor) executeSshKey(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, ok := action.Parameters["target"].(string)
	if !ok {
		return "", fmt.Errorf("target parameter required for ssh_key")
	}

	username, ok := action.Parameters["username"].(string)
	if !ok {
		return "", fmt.Errorf("username parameter required for ssh_key")
	}

	keyPath, ok := action.Parameters["key"].(string)
	if !ok {
		return "", fmt.Errorf("key parameter required for ssh_key")
	}

	var port int
	if portVal, ok := action.Parameters["port"]; ok {
		switch v := portVal.(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		default:
			return "", fmt.Errorf("port parameter must be a number")
		}
	} else {
		port = 22 // default SSH port
	}

	resp, err := client.SpawnSshKey(ctx, beaconID, target, port, username, keyPath)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeRemoteExec executes a command on a target via specific remote execution method
func (e *Executor) executeRemoteExec(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	method, ok := action.Parameters["method"].(string)
	if !ok {
		return "", fmt.Errorf("method parameter required for remote_exec")
	}

	target, ok := action.Parameters["target"].(string)
	if !ok {
		return "", fmt.Errorf("target parameter required for remote_exec")
	}

	command, ok := action.Parameters["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required for remote_exec")
	}

	resp, err := client.RemoteExec(ctx, beaconID, method, target, command)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeJump executes a beacon session on a remote target with the specified remote execution method
func (e *Executor) executeJump(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	exploit, ok := action.Parameters["exploit"].(string)
	if !ok {
		return "", fmt.Errorf("exploit parameter required for jump")
	}

	target, ok := action.Parameters["target"].(string)
	if !ok {
		return "", fmt.Errorf("target parameter required for jump")
	}

	listener, ok := action.Parameters["listener"].(string)
	if !ok {
		return "", fmt.Errorf("listener parameter required for jump")
	}

	resp, err := client.Jump(ctx, beaconID, exploit, target, listener)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// --- Tunneling Handlers ---

// executeSocks4Start starts a SOCKS4a server on the specified port
func (e *Executor) executeSocks4Start(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	portVal, ok := action.Parameters["port"]
	if !ok {
		return "", fmt.Errorf("port parameter required for socks4_start")
	}

	var port int
	switch v := portVal.(type) {
	case float64:
		port = int(v)
	case int:
		port = v
	default:
		return "", fmt.Errorf("port parameter must be a number")
	}

	resp, err := client.Socks4Start(ctx, beaconID, port)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, fmt.Sprintf("socks4 start port %d", port))
}

// executeSocks5Start starts a SOCKS5 server on the specified port with optional authentication
func (e *Executor) executeSocks5Start(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	portVal, ok := action.Parameters["port"]
	if !ok {
		return "", fmt.Errorf("port parameter required for socks5_start")
	}

	var port int
	switch v := portVal.(type) {
	case float64:
		port = int(v)
	case int:
		port = v
	default:
		return "", fmt.Errorf("port parameter must be a number")
	}

	// Optional authentication
	var auth *csclient.SocksAuthDto
	if authMap, ok := action.Parameters["auth"].(map[string]interface{}); ok {
		user, _ := authMap["user"].(string)
		password, _ := authMap["password"].(string)
		auth = &csclient.SocksAuthDto{
			User:     user,
			Password: password,
		}
	}

	// Optional logging
	enableLogging, _ := action.Parameters["enable_logging"].(bool)

	resp, err := client.Socks5Start(ctx, beaconID, port, auth, enableLogging)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, fmt.Sprintf("socks5 start port %d", port))
}

// executeSocksStopAll stops all SOCKS servers and terminates existing connections
func (e *Executor) executeSocksStopAll(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	resp, err := client.SocksStopAll(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, "socks stop all")
}

// executeSocksStop stops the specific SOCKS server on the given port
func (e *Executor) executeSocksStop(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	portVal, ok := action.Parameters["port"]
	if !ok {
		return "", fmt.Errorf("port parameter required for socks_stop")
	}

	var port int
	switch v := portVal.(type) {
	case float64:
		port = int(v)
	case int:
		port = v
	default:
		return "", fmt.Errorf("port parameter must be a number")
	}

	resp, err := client.SocksStop(ctx, beaconID, port)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, fmt.Sprintf("socks stop port %d", port))
}

// executeRportfwdStart starts reverse port forwarding on the specified bind port
func (e *Executor) executeRportfwdStart(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	bindPortVal, ok := action.Parameters["bind_port"]
	if !ok {
		return "", fmt.Errorf("bind_port parameter required for rportfwd_start")
	}

	var bindPort int
	switch v := bindPortVal.(type) {
	case float64:
		bindPort = int(v)
	case int:
		bindPort = v
	default:
		return "", fmt.Errorf("bind_port parameter must be a number")
	}

	forwardHost, ok := action.Parameters["forward_host"].(string)
	if !ok {
		return "", fmt.Errorf("forward_host parameter required for rportfwd_start")
	}

	forwardPortVal, ok := action.Parameters["forward_port"]
	if !ok {
		return "", fmt.Errorf("forward_port parameter required for rportfwd_start")
	}

	var forwardPort int
	switch v := forwardPortVal.(type) {
	case float64:
		forwardPort = int(v)
	case int:
		forwardPort = v
	default:
		return "", fmt.Errorf("forward_port parameter must be a number")
	}

	resp, err := client.RportfwdStart(ctx, beaconID, bindPort, forwardHost, forwardPort)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, fmt.Sprintf("rportfwd start %d -> %s:%d", bindPort, forwardHost, forwardPort))
}

// executeRportfwdStop stops reverse port forwarding on the specific bind port
func (e *Executor) executeRportfwdStop(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	bindPortVal, ok := action.Parameters["bind_port"]
	if !ok {
		return "", fmt.Errorf("bind_port parameter required for rportfwd_stop")
	}

	var bindPort int
	switch v := bindPortVal.(type) {
	case float64:
		bindPort = int(v)
	case int:
		bindPort = v
	default:
		return "", fmt.Errorf("bind_port parameter must be a number")
	}

	resp, err := client.RportfwdStop(ctx, beaconID, bindPort)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, fmt.Sprintf("rportfwd stop %d", bindPort))
}

// executeBrowserPivotStart starts a browser pivot into the specified process
func (e *Executor) executeBrowserPivotStart(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for browser_pivot_start")
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

	arch, ok := action.Parameters["arch"].(string)
	if !ok {
		return "", fmt.Errorf("arch parameter required for browser_pivot_start")
	}

	// Validate arch
	if arch != "x86" && arch != "x64" {
		return "", fmt.Errorf("arch parameter must be 'x86' or 'x64'")
	}

	resp, err := client.BrowserPivotStart(ctx, beaconID, pid, arch)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, fmt.Sprintf("browser pivot start pid %d", pid))
}

// executeBrowserPivotStop tears down the browser pivoting sessions associated with this beacon
func (e *Executor) executeBrowserPivotStop(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	resp, err := client.BrowserPivotStop(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.fireAndForget(resp.TaskID, "browser pivot stop")
}
