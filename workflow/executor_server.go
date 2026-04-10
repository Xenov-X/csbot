package workflow

import (
	"context"
	"encoding/json"
	"fmt"

	csclient "github.com/xenov-x/csrest"
)

// ============================================================
// Server-Level Action Handlers
// These operations do NOT require a beacon ID and return
// synchronous responses (no task polling needed).
// ============================================================

// --- Listener Management ---

// executeListListeners lists all configured listeners
func (e *Executor) executeListListeners(ctx context.Context, client *csclient.Client) (string, error) {
	e.logInfo("Listing all listeners")
	listeners, err := client.ListListeners(ctx)
	if err != nil {
		return "", fmt.Errorf("list listeners failed: %w", err)
	}
	data, _ := json.MarshalIndent(listeners, "", "  ")
	return string(data), nil
}

// executeGetListener retrieves a specific listener by name
func (e *Executor) executeGetListener(ctx context.Context, client *csclient.Client, action Action) (string, error) {
	name, ok := action.Parameters["name"].(string)
	if !ok {
		return "", fmt.Errorf("name parameter required for get_listener")
	}

	e.logInfo("Getting listener: %s", name)
	listener, err := client.GetListener(ctx, name)
	if err != nil {
		return "", fmt.Errorf("get listener failed: %w", err)
	}
	data, _ := json.MarshalIndent(listener, "", "  ")
	return string(data), nil
}

// executeDeleteListener removes a listener by name
func (e *Executor) executeDeleteListener(ctx context.Context, client *csclient.Client, action Action) (string, error) {
	name, ok := action.Parameters["name"].(string)
	if !ok {
		return "", fmt.Errorf("name parameter required for delete_listener")
	}

	e.logInfo("Deleting listener: %s", name)
	if err := client.DeleteListener(ctx, name); err != nil {
		return "", fmt.Errorf("delete listener failed: %w", err)
	}
	return fmt.Sprintf("listener '%s' deleted", name), nil
}

// executeAddListener is a generic handler for all add_*_listener action types.
// It passes the entire parameters map to the corresponding csrest method.
func (e *Executor) executeAddListener(ctx context.Context, client *csclient.Client, action Action, listenerType string) (string, error) {
	// Build config from parameters
	config := make(map[string]interface{})
	for k, v := range action.Parameters {
		config[k] = v
	}

	e.logInfo("Adding %s listener: %s", listenerType, config["name"])

	var resp map[string]interface{}
	var err error

	switch listenerType {
	case "http":
		resp, err = client.AddHttpListener(ctx, config)
	case "https":
		resp, err = client.AddHttpsListener(ctx, config)
	case "dns":
		resp, err = client.AddDnsListener(ctx, config)
	case "tcp":
		resp, err = client.AddTcpListener(ctx, config)
	case "smb":
		resp, err = client.AddSmbListener(ctx, config)
	case "externalc2":
		resp, err = client.AddExternalC2Listener(ctx, config)
	case "udc2":
		resp, err = client.AddUserDefinedC2Listener(ctx, config)
	case "foreign_http":
		resp, err = client.AddForeignHttpListener(ctx, config)
	case "foreign_https":
		resp, err = client.AddForeignHttpsListener(ctx, config)
	default:
		return "", fmt.Errorf("unknown listener type: %s", listenerType)
	}

	if err != nil {
		return "", fmt.Errorf("add %s listener failed: %w", listenerType, err)
	}
	data, _ := json.MarshalIndent(resp, "", "  ")
	return string(data), nil
}

// executeUpdateListener is a generic handler for all update_*_listener action types.
func (e *Executor) executeUpdateListener(ctx context.Context, client *csclient.Client, action Action, listenerType string) (string, error) {
	name, ok := action.Parameters["name"].(string)
	if !ok {
		return "", fmt.Errorf("name parameter required for update_%s_listener", listenerType)
	}

	// Build config from parameters (pass everything including name)
	config := make(map[string]interface{})
	for k, v := range action.Parameters {
		config[k] = v
	}

	e.logInfo("Updating %s listener: %s", listenerType, name)

	var resp map[string]interface{}
	var err error

	switch listenerType {
	case "http":
		resp, err = client.UpdateHttpListener(ctx, name, config)
	case "https":
		resp, err = client.UpdateHttpsListener(ctx, name, config)
	case "dns":
		resp, err = client.UpdateDnsListener(ctx, name, config)
	case "tcp":
		resp, err = client.UpdateTcpListener(ctx, name, config)
	case "smb":
		resp, err = client.UpdateSmbListener(ctx, name, config)
	case "externalc2":
		resp, err = client.UpdateExternalC2Listener(ctx, name, config)
	case "udc2":
		resp, err = client.UpdateUserDefinedC2Listener(ctx, name, config)
	case "foreign_http":
		resp, err = client.UpdateForeignHttpListener(ctx, name, config)
	case "foreign_https":
		resp, err = client.UpdateForeignHttpsListener(ctx, name, config)
	default:
		return "", fmt.Errorf("unknown listener type: %s", listenerType)
	}

	if err != nil {
		return "", fmt.Errorf("update %s listener failed: %w", listenerType, err)
	}
	data, _ := json.MarshalIndent(resp, "", "  ")
	return string(data), nil
}

// --- Payload Operations ---

// executeListArtifacts lists all server-side artifacts (generated payloads)
func (e *Executor) executeListArtifacts(ctx context.Context, client *csclient.Client) (string, error) {
	e.logInfo("Listing all artifacts")
	artifacts, err := client.ListArtifacts(ctx)
	if err != nil {
		return "", fmt.Errorf("list artifacts failed: %w", err)
	}
	data, _ := json.MarshalIndent(artifacts, "", "  ")
	return string(data), nil
}

// executeGenerateStagelessPayload generates a stageless beacon payload
func (e *Executor) executeGenerateStagelessPayload(ctx context.Context, client *csclient.Client, action Action) (string, error) {
	config := make(map[string]interface{})
	for k, v := range action.Parameters {
		config[k] = v
	}

	e.logInfo("Generating stageless payload for listener: %s", config["listenerName"])
	result, err := client.GenerateStagelessPayload(ctx, config)
	if err != nil {
		return "", fmt.Errorf("generate stageless payload failed: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("payload generation error: %s", result.Error)
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data), nil
}

// executeGenerateStagerPayload generates a stager beacon payload
func (e *Executor) executeGenerateStagerPayload(ctx context.Context, client *csclient.Client, action Action) (string, error) {
	config := make(map[string]interface{})
	for k, v := range action.Parameters {
		config[k] = v
	}

	e.logInfo("Generating stager payload for listener: %s", config["listenerName"])
	result, err := client.GenerateStagerPayload(ctx, config)
	if err != nil {
		return "", fmt.Errorf("generate stager payload failed: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("stager generation error: %s", result.Error)
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data), nil
}

// executeDownloadPayload downloads a previously generated payload
func (e *Executor) executeDownloadPayload(ctx context.Context, client *csclient.Client, action Action) (string, error) {
	fileName, ok := action.Parameters["file_name"].(string)
	if !ok {
		return "", fmt.Errorf("file_name parameter required for download_payload")
	}

	e.logInfo("Downloading payload: %s", fileName)
	_, err := client.DownloadPayload(ctx, fileName)
	if err != nil {
		return "", fmt.Errorf("download payload failed: %w", err)
	}
	// Note: actual binary data handling would need a file write destination
	return fmt.Sprintf("payload '%s' downloaded", fileName), nil
}

// --- Server Config Operations ---

// executeGetKillDate retrieves the beacon kill date
func (e *Executor) executeGetKillDate(ctx context.Context, client *csclient.Client) (string, error) {
	e.logInfo("Getting kill date")
	resp, err := client.GetKillDate(ctx)
	if err != nil {
		return "", fmt.Errorf("get kill date failed: %w", err)
	}
	return resp, nil
}

// executeGetC2Profile retrieves the Malleable C2 profile
func (e *Executor) executeGetC2Profile(ctx context.Context, client *csclient.Client) (string, error) {
	e.logInfo("Getting C2 profile")
	resp, err := client.GetC2Profile(ctx)
	if err != nil {
		return "", fmt.Errorf("get c2 profile failed: %w", err)
	}
	return resp, nil
}

// executeGetSystemInfo retrieves team server system information
func (e *Executor) executeGetSystemInfo(ctx context.Context, client *csclient.Client) (string, error) {
	e.logInfo("Getting system information")
	resp, err := client.GetSystemInformation(ctx)
	if err != nil {
		return "", fmt.Errorf("get system information failed: %w", err)
	}
	return resp, nil
}

// executeGetTeamserverIp retrieves the team server IP
func (e *Executor) executeGetTeamserverIp(ctx context.Context, client *csclient.Client) (string, error) {
	e.logInfo("Getting teamserver IP")
	resp, err := client.GetTeamserverIp(ctx)
	if err != nil {
		return "", fmt.Errorf("get teamserver ip failed: %w", err)
	}
	return resp, nil
}
