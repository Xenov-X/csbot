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

	// Warn if workflow has beacon-targeted actions but no beacon_id
	if wf.BeaconID == "" && WorkflowRequiresBeacon(wf) {
		errors = append(errors, ValidationError{
			Type:     "workflow",
			Message:  "workflow contains beacon-targeted actions but no beacon_id specified (will prompt for selection)",
			Severity: "warning",
		})
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
		// File & directory operations
		"cd":        true,
		"ls":        true,
		"pwd":       true,
		"mkdir":     true,
		"cp":        true,
		"mv":        true,
		"rm":        true,
		"drives":    true,
		"timestomp": true,
		// Process management operations
		"ps":       true,
		"kill":     true,
		"getprivs": true,
		"setenv":   true,
		"exit":     true,
		"job_stop": true,
		// Credential & token operations
		"steal_token":           true,
		"make_token":            true,
		"make_token_upn":        true,
		"rev2self":              true,
		"kerberos_ticket_use":   true,
		"kerberos_ticket_purge": true,
		"token_store_steal":     true,
		"token_store_steal_use": true,
		"token_store_use":       true,
		"token_store_remove":    true,
		"token_store_remove_all": true,
		"token_store_list":      true,
		"hashdump":              true,
		"logon_passwords":       true,
		"mimikatz":              true,
		"dcsync":                true,
		"chromedump":            true,
		// Pivoting & lateral movement
		"link_smb":     true,
		"link_tcp":     true,
		"unlink":       true,
		"ssh":          true,
		"ssh_key":      true,
		"remote_exec":  true,
		"jump":         true,
		// Tunneling
		"socks4_start":       true,
		"socks5_start":       true,
		"socks_stop_all":     true,
		"socks_stop":         true,
		"rportfwd_start":     true,
		"rportfwd_stop":      true,
		"browser_pivot_start": true,
		"browser_pivot_stop": true,
		// Network recon
		"net_domain":             true,
		"net_view":               true,
		"net_user":               true,
		"net_user_detail":        true,
		"net_time":               true,
		"net_share":              true,
		"net_sessions":           true,
		"net_logons":             true,
		"net_localgroup":         true,
		"net_group":              true,
		"net_domain_trusts":      true,
		"net_domain_controllers": true,
		"net_dclist":             true,
		"net_computers":          true,
		"portscan":               true,
		// Capture operations
		"keylogger":        true,
		"screenwatch":      true,
		"printscreen":      true,
		"clipboard":        true,
		"cancel_download":  true,
		// Command execution variants
		"run":           true,
		"runas":         true,
		"run_under":     true,
		"run_no_output": true,
		// Privilege elevation
		"elevate_command": true,
		"elevate_beacon":  true,
		// Beacon/shellcode spawn & inject
		"spawn_beacon":         true,
		"spawn_beacon_as_user": true,
		"spawn_beacon_under":   true,
		"inject_beacon":        true,
		"spawn_shellcode":      true,
		"inject_shellcode":     true,
		// PowerShell & .NET
		"powershell_import": true,
		"powerpick":         true,
		"psinject":          true,
		"execute_assembly":  true,
		// Pass-the-hash
		"spawn_pth":  true,
		"inject_pth": true,
		// DLL operations
		"inject_dll":      true,
		"inject_load_dll": true,
		// PostEx DLL
		"spawn_postex_dll":  true,
		"inject_postex_dll": true,
		// Registry
		"reg_query":  true,
		"reg_queryv": true,
		// Beacon configuration
		"beacon_info":         true,
		"set_sleep":           true,
		"set_note":            true,
		"enable_beacon_gate":  true,
		"disable_beacon_gate": true,
		"enable_blockdlls":    true,
		"disable_blockdlls":   true,
		"set_spawnto":         true,
		"unset_spawnto":       true,
		"set_ppid":            true,
		"unset_ppid":          true,
		"set_dns_mode":        true,
		"set_syscall_method":  true,
		// Beacon management
		"delete_beacon":    true,
		"clear_queue":      true,
		"checkin":          true,
		"console_command":  true,
		"list_jobs":        true,
		// Server-level operations (no beacon required)
		"list_listeners":              true,
		"get_listener":                true,
		"delete_listener":             true,
		"add_http_listener":           true,
		"add_https_listener":          true,
		"add_dns_listener":            true,
		"add_tcp_listener":            true,
		"add_smb_listener":            true,
		"add_externalc2_listener":     true,
		"add_udc2_listener":           true,
		"add_foreign_http_listener":   true,
		"add_foreign_https_listener":  true,
		"update_http_listener":        true,
		"update_https_listener":       true,
		"update_dns_listener":         true,
		"update_tcp_listener":         true,
		"update_smb_listener":         true,
		"update_externalc2_listener":  true,
		"update_udc2_listener":        true,
		"update_foreign_http_listener":  true,
		"update_foreign_https_listener": true,
		"list_artifacts":              true,
		"generate_stageless_payload":  true,
		"generate_stager_payload":     true,
		"download_payload":            true,
		"get_kill_date":               true,
		"get_c2_profile":              true,
		"get_system_info":             true,
		"get_teamserver_ip":           true,
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

	// Validate cd action
	if action.Type == "cd" {
		if action.Parameters == nil || action.Parameters["path"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "cd action requires 'path' parameter",
			})
		}
	}

	// Validate mkdir action
	if action.Type == "mkdir" {
		if action.Parameters == nil || action.Parameters["folder"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "mkdir action requires 'folder' parameter",
			})
		}
	}

	// Validate cp action
	if action.Type == "cp" {
		if action.Parameters == nil || action.Parameters["src"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "cp action requires 'src' parameter",
			})
		}
		if action.Parameters == nil || action.Parameters["dst"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "cp action requires 'dst' parameter",
			})
		}
	}

	// Validate mv action
	if action.Type == "mv" {
		if action.Parameters == nil || action.Parameters["source"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "mv action requires 'source' parameter",
			})
		}
		if action.Parameters == nil || action.Parameters["destination"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "mv action requires 'destination' parameter",
			})
		}
	}

	// Validate rm action
	if action.Type == "rm" {
		if action.Parameters == nil || action.Parameters["path"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "rm action requires 'path' parameter",
			})
		}
	}

	// Validate timestomp action
	if action.Type == "timestomp" {
		if action.Parameters == nil || action.Parameters["source"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "timestomp action requires 'source' parameter",
			})
		}
		if action.Parameters == nil || action.Parameters["destination"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "timestomp action requires 'destination' parameter",
			})
		}
	}

	// Validate kill action
	if action.Type == "kill" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "kill action requires 'pid' parameter",
			})
		}
	}

	// Validate setenv action
	if action.Type == "setenv" {
		if action.Parameters == nil || action.Parameters["key"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "setenv action requires 'key' parameter",
			})
		}
	}

	// Validate job_stop action
	if action.Type == "job_stop" {
		if action.Parameters == nil || action.Parameters["jid"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "job_stop action requires 'jid' parameter",
			})
		}
	}

	// --- Credential & Token Operations ---

	// Validate steal_token action
	if action.Type == "steal_token" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "steal_token action requires 'pid' parameter",
			})
		}
	}

	// Validate make_token action
	if action.Type == "make_token" {
		if action.Parameters == nil || action.Parameters["user"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "make_token action requires 'user' parameter",
			})
		}
		if action.Parameters == nil || action.Parameters["password"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "make_token action requires 'password' parameter",
			})
		}
	}

	// Validate make_token_upn action
	if action.Type == "make_token_upn" {
		if action.Parameters == nil || action.Parameters["upn"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "make_token_upn action requires 'upn' parameter",
			})
		}
		if action.Parameters == nil || action.Parameters["password"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "make_token_upn action requires 'password' parameter",
			})
		}
	}

	// Validate kerberos_ticket_use action
	if action.Type == "kerberos_ticket_use" {
		if action.Parameters == nil || action.Parameters["ticket"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "kerberos_ticket_use action requires 'ticket' parameter",
			})
		}
	}

	// Validate token_store_steal action
	if action.Type == "token_store_steal" || action.Type == "token_store_steal_use" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: fmt.Sprintf("%s action requires 'pid' parameter", action.Type),
			})
		}
	}

	// Validate token_store_use and token_store_remove actions
	if action.Type == "token_store_use" || action.Type == "token_store_remove" {
		if action.Parameters == nil || action.Parameters["id"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: fmt.Sprintf("%s action requires 'id' parameter", action.Type),
			})
		}
	}

	// Validate mimikatz action
	if action.Type == "mimikatz" {
		if action.Parameters == nil || action.Parameters["command"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "mimikatz action requires 'command' parameter",
			})
		}
	}

	// Validate dcsync action
	if action.Type == "dcsync" {
		if action.Parameters == nil || action.Parameters["domain"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "dcsync action requires 'domain' parameter",
			})
		}
	}

	// --- Pivoting & Lateral Movement ---

	// Validate link_smb action
	if action.Type == "link_smb" {
		if action.Parameters == nil || action.Parameters["target"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "link_smb action requires 'target' parameter",
			})
		}
	}

	// Validate link_tcp action
	if action.Type == "link_tcp" {
		if action.Parameters == nil || action.Parameters["target"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "link_tcp action requires 'target' parameter",
			})
		}
	}

	// Validate unlink action
	if action.Type == "unlink" {
		if action.Parameters == nil || action.Parameters["host"] == nil {
			errors = append(errors, ValidationError{
				Type:    prefix,
				Message: "unlink action requires 'host' parameter",
			})
		}
	}

	// Validate ssh action
	if action.Type == "ssh" {
		if action.Parameters == nil || action.Parameters["target"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "ssh action requires 'target' parameter"})
		}
		if action.Parameters == nil || action.Parameters["username"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "ssh action requires 'username' parameter"})
		}
		if action.Parameters == nil || action.Parameters["password"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "ssh action requires 'password' parameter"})
		}
	}

	// Validate ssh_key action
	if action.Type == "ssh_key" {
		if action.Parameters == nil || action.Parameters["target"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "ssh_key action requires 'target' parameter"})
		}
		if action.Parameters == nil || action.Parameters["username"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "ssh_key action requires 'username' parameter"})
		}
		if action.Parameters == nil || action.Parameters["key"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "ssh_key action requires 'key' parameter"})
		}
	}

	// Validate remote_exec action
	if action.Type == "remote_exec" {
		if action.Parameters == nil || action.Parameters["method"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "remote_exec action requires 'method' parameter"})
		}
		if action.Parameters == nil || action.Parameters["target"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "remote_exec action requires 'target' parameter"})
		}
		if action.Parameters == nil || action.Parameters["command"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "remote_exec action requires 'command' parameter"})
		}
	}

	// Validate jump action
	if action.Type == "jump" {
		if action.Parameters == nil || action.Parameters["exploit"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "jump action requires 'exploit' parameter"})
		}
		if action.Parameters == nil || action.Parameters["target"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "jump action requires 'target' parameter"})
		}
		if action.Parameters == nil || action.Parameters["listener"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "jump action requires 'listener' parameter"})
		}
	}

	// --- Tunneling ---

	// Validate socks4_start action
	if action.Type == "socks4_start" {
		if action.Parameters == nil || action.Parameters["port"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "socks4_start action requires 'port' parameter"})
		}
	}

	// Validate socks5_start action
	if action.Type == "socks5_start" {
		if action.Parameters == nil || action.Parameters["port"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "socks5_start action requires 'port' parameter"})
		}
	}

	// Validate socks_stop action
	if action.Type == "socks_stop" {
		if action.Parameters == nil || action.Parameters["port"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "socks_stop action requires 'port' parameter"})
		}
	}

	// Validate rportfwd_start action
	if action.Type == "rportfwd_start" {
		if action.Parameters == nil || action.Parameters["bind_port"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "rportfwd_start action requires 'bind_port' parameter"})
		}
		if action.Parameters == nil || action.Parameters["forward_host"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "rportfwd_start action requires 'forward_host' parameter"})
		}
		if action.Parameters == nil || action.Parameters["forward_port"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "rportfwd_start action requires 'forward_port' parameter"})
		}
	}

	// Validate rportfwd_stop action
	if action.Type == "rportfwd_stop" {
		if action.Parameters == nil || action.Parameters["bind_port"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "rportfwd_stop action requires 'bind_port' parameter"})
		}
	}

	// Validate browser_pivot_start action
	if action.Type == "browser_pivot_start" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "browser_pivot_start action requires 'pid' parameter"})
		}
		if action.Parameters == nil || action.Parameters["arch"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "browser_pivot_start action requires 'arch' parameter"})
		}
	}

	// --- Network Recon ---

	// Validate portscan action
	if action.Type == "portscan" {
		if action.Parameters == nil || action.Parameters["targets"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "portscan action requires 'targets' parameter"})
		}
		if action.Parameters == nil || action.Parameters["ports"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "portscan action requires 'ports' parameter"})
		}
	}

	// --- Capture Operations ---

	// Validate cancel_download action
	if action.Type == "cancel_download" {
		if action.Parameters == nil || action.Parameters["file"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "cancel_download action requires 'file' parameter"})
		}
	}

	// --- Command Execution Variants ---

	// Validate run action
	if action.Type == "run" {
		if action.Parameters == nil || action.Parameters["program"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "run action requires 'program' parameter"})
		}
	}

	// Validate runas action
	if action.Type == "runas" {
		if action.Parameters == nil || action.Parameters["user"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "runas action requires 'user' parameter"})
		}
		if action.Parameters == nil || action.Parameters["password"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "runas action requires 'password' parameter"})
		}
		if action.Parameters == nil || action.Parameters["command"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "runas action requires 'command' parameter"})
		}
	}

	// Validate run_under action
	if action.Type == "run_under" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "run_under action requires 'pid' parameter"})
		}
		if action.Parameters == nil || action.Parameters["command"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "run_under action requires 'command' parameter"})
		}
	}

	// Validate run_no_output action
	if action.Type == "run_no_output" {
		if action.Parameters == nil || action.Parameters["command"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "run_no_output action requires 'command' parameter"})
		}
	}

	// --- Privilege Elevation ---

	// Validate elevate_command action
	if action.Type == "elevate_command" {
		if action.Parameters == nil || action.Parameters["exploit"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "elevate_command action requires 'exploit' parameter"})
		}
		if action.Parameters == nil || action.Parameters["command"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "elevate_command action requires 'command' parameter"})
		}
	}

	// Validate elevate_beacon action
	if action.Type == "elevate_beacon" {
		if action.Parameters == nil || action.Parameters["exploit"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "elevate_beacon action requires 'exploit' parameter"})
		}
		if action.Parameters == nil || action.Parameters["listener"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "elevate_beacon action requires 'listener' parameter"})
		}
	}

	// --- Beacon/Shellcode Spawn & Inject ---

	// Validate spawn_beacon action
	if action.Type == "spawn_beacon" {
		if action.Parameters == nil || action.Parameters["listener"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "spawn_beacon action requires 'listener' parameter"})
		}
	}

	// Validate spawn_beacon_as_user action
	if action.Type == "spawn_beacon_as_user" {
		if action.Parameters == nil || action.Parameters["password"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "spawn_beacon_as_user action requires 'password' parameter"})
		}
		if action.Parameters == nil || action.Parameters["listener"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "spawn_beacon_as_user action requires 'listener' parameter"})
		}
	}

	// Validate spawn_beacon_under action
	if action.Type == "spawn_beacon_under" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "spawn_beacon_under action requires 'pid' parameter"})
		}
		if action.Parameters == nil || action.Parameters["listener"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "spawn_beacon_under action requires 'listener' parameter"})
		}
	}

	// Validate inject_beacon action
	if action.Type == "inject_beacon" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_beacon action requires 'pid' parameter"})
		}
		if action.Parameters == nil || action.Parameters["listener"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_beacon action requires 'listener' parameter"})
		}
	}

	// Validate spawn_shellcode action
	if action.Type == "spawn_shellcode" {
		if action.Parameters == nil || action.Parameters["arch"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "spawn_shellcode action requires 'arch' parameter"})
		}
		if action.Parameters == nil || action.Parameters["shellcode"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "spawn_shellcode action requires 'shellcode' parameter"})
		}
	}

	// Validate inject_shellcode action
	if action.Type == "inject_shellcode" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_shellcode action requires 'pid' parameter"})
		}
		if action.Parameters == nil || action.Parameters["arch"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_shellcode action requires 'arch' parameter"})
		}
		if action.Parameters == nil || action.Parameters["shellcode"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_shellcode action requires 'shellcode' parameter"})
		}
	}

	// --- PowerShell & .NET ---

	// Validate powershell_import action
	if action.Type == "powershell_import" {
		if action.Parameters == nil || action.Parameters["script"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "powershell_import action requires 'script' parameter"})
		}
	}

	// Validate powerpick action
	if action.Type == "powerpick" {
		if action.Parameters == nil || action.Parameters["commandlet"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "powerpick action requires 'commandlet' parameter"})
		}
	}

	// Validate psinject action
	if action.Type == "psinject" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "psinject action requires 'pid' parameter"})
		}
		if action.Parameters == nil || action.Parameters["arch"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "psinject action requires 'arch' parameter"})
		}
		if action.Parameters == nil || action.Parameters["commandlet"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "psinject action requires 'commandlet' parameter"})
		}
	}

	// Validate execute_assembly action
	if action.Type == "execute_assembly" {
		if action.Parameters == nil || action.Parameters["assembly"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "execute_assembly action requires 'assembly' parameter"})
		}
	}

	// --- Pass-the-Hash ---

	// Validate spawn_pth action
	if action.Type == "spawn_pth" {
		if action.Parameters == nil || action.Parameters["user"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "spawn_pth action requires 'user' parameter"})
		}
		if action.Parameters == nil || action.Parameters["ntlm_hash"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "spawn_pth action requires 'ntlm_hash' parameter"})
		}
	}

	// Validate inject_pth action
	if action.Type == "inject_pth" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_pth action requires 'pid' parameter"})
		}
		if action.Parameters == nil || action.Parameters["user"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_pth action requires 'user' parameter"})
		}
		if action.Parameters == nil || action.Parameters["ntlm_hash"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_pth action requires 'ntlm_hash' parameter"})
		}
	}

	// --- DLL Operations ---

	// Validate inject_dll action
	if action.Type == "inject_dll" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_dll action requires 'pid' parameter"})
		}
		if action.Parameters == nil || action.Parameters["dll"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_dll action requires 'dll' parameter"})
		}
	}

	// Validate inject_load_dll action
	if action.Type == "inject_load_dll" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_load_dll action requires 'pid' parameter"})
		}
		if action.Parameters == nil || action.Parameters["path"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_load_dll action requires 'path' parameter"})
		}
	}

	// --- PostEx DLL ---

	// Validate spawn_postex_dll action
	if action.Type == "spawn_postex_dll" {
		if action.Parameters == nil || action.Parameters["dll"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "spawn_postex_dll action requires 'dll' parameter"})
		}
	}

	// Validate inject_postex_dll action
	if action.Type == "inject_postex_dll" {
		if action.Parameters == nil || action.Parameters["pid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_postex_dll action requires 'pid' parameter"})
		}
		if action.Parameters == nil || action.Parameters["dll"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "inject_postex_dll action requires 'dll' parameter"})
		}
	}

	// --- Registry ---

	// Validate reg_query action
	if action.Type == "reg_query" {
		if action.Parameters == nil || action.Parameters["arch"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "reg_query action requires 'arch' parameter"})
		}
		if action.Parameters == nil || action.Parameters["path"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "reg_query action requires 'path' parameter"})
		}
	}

	// Validate reg_queryv action
	if action.Type == "reg_queryv" {
		if action.Parameters == nil || action.Parameters["arch"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "reg_queryv action requires 'arch' parameter"})
		}
		if action.Parameters == nil || action.Parameters["path"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "reg_queryv action requires 'path' parameter"})
		}
		if action.Parameters == nil || action.Parameters["subkey"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "reg_queryv action requires 'subkey' parameter"})
		}
	}

	// --- Beacon Configuration ---

	// Validate set_sleep action
	if action.Type == "set_sleep" {
		if action.Parameters == nil || action.Parameters["sleep"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "set_sleep action requires 'sleep' parameter"})
		}
		if action.Parameters == nil || action.Parameters["jitter"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "set_sleep action requires 'jitter' parameter"})
		}
	}

	// Validate set_note action
	if action.Type == "set_note" {
		if action.Parameters == nil || action.Parameters["note"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "set_note action requires 'note' parameter"})
		}
	}

	// Validate set_spawnto action
	if action.Type == "set_spawnto" {
		if action.Parameters == nil || action.Parameters["arch"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "set_spawnto action requires 'arch' parameter"})
		}
		if action.Parameters == nil || action.Parameters["path"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "set_spawnto action requires 'path' parameter"})
		}
	}

	// Validate set_ppid action
	if action.Type == "set_ppid" {
		if action.Parameters == nil || action.Parameters["ppid"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "set_ppid action requires 'ppid' parameter"})
		}
	}

	// Validate set_dns_mode action
	if action.Type == "set_dns_mode" {
		if action.Parameters == nil || action.Parameters["mode"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "set_dns_mode action requires 'mode' parameter"})
		}
	}

	// Validate set_syscall_method action
	if action.Type == "set_syscall_method" {
		if action.Parameters == nil || action.Parameters["method"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "set_syscall_method action requires 'method' parameter"})
		}
	}

	// --- Beacon Management ---

	// Validate console_command action
	if action.Type == "console_command" {
		if action.Parameters == nil || action.Parameters["command"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "console_command action requires 'command' parameter"})
		}
	}

	// --- Server-Level Operations ---

	// Validate get_listener action
	if action.Type == "get_listener" || action.Type == "delete_listener" {
		if action.Parameters == nil || action.Parameters["name"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: fmt.Sprintf("%s action requires 'name' parameter", action.Type)})
		}
	}

	// Validate add_*_listener actions (all require 'name')
	if strings.HasPrefix(action.Type, "add_") && strings.HasSuffix(action.Type, "_listener") {
		if action.Parameters == nil || action.Parameters["name"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: fmt.Sprintf("%s action requires 'name' parameter", action.Type)})
		}
	}

	// Validate update_*_listener actions (all require 'name')
	if strings.HasPrefix(action.Type, "update_") && strings.HasSuffix(action.Type, "_listener") {
		if action.Parameters == nil || action.Parameters["name"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: fmt.Sprintf("%s action requires 'name' parameter", action.Type)})
		}
	}

	// Validate generate_stageless_payload action
	if action.Type == "generate_stageless_payload" {
		if action.Parameters == nil || action.Parameters["listenerName"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "generate_stageless_payload action requires 'listenerName' parameter"})
		}
		if action.Parameters == nil || action.Parameters["architecture"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "generate_stageless_payload action requires 'architecture' parameter"})
		}
		if action.Parameters == nil || (action.Parameters["output"] == nil && action.Parameters["format"] == nil) {
			errors = append(errors, ValidationError{Type: prefix, Message: "generate_stageless_payload action requires 'output' parameter (payload format: Raw, C, C#, Java, etc.)"})
		}
		if action.Parameters == nil || action.Parameters["fileName"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "generate_stageless_payload action requires 'fileName' parameter"})
		}
	}

	// Validate generate_stager_payload action
	if action.Type == "generate_stager_payload" {
		if action.Parameters == nil || action.Parameters["listenerName"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "generate_stager_payload action requires 'listenerName' parameter"})
		}
		if action.Parameters == nil || action.Parameters["architecture"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "generate_stager_payload action requires 'architecture' parameter"})
		}
		if action.Parameters == nil || (action.Parameters["output"] == nil && action.Parameters["format"] == nil) {
			errors = append(errors, ValidationError{Type: prefix, Message: "generate_stager_payload action requires 'output' parameter (payload format: Raw, C, C#, Java, etc.)"})
		}
		if action.Parameters == nil || action.Parameters["fileName"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "generate_stager_payload action requires 'fileName' parameter"})
		}
	}

	// Validate download_payload action
	if action.Type == "download_payload" {
		if action.Parameters == nil || action.Parameters["file_name"] == nil {
			errors = append(errors, ValidationError{Type: prefix, Message: "download_payload action requires 'file_name' parameter"})
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

	// Check if BOF file exists (if not using @files/ prefix)
	if !strings.HasPrefix(bofPath, "@files/") && !strings.HasPrefix(bofPath, "@artifacts/") {
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
