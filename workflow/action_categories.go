package workflow

// serverActionTypes lists action types that do NOT require a beacon.
// These are server-level operations (listeners, payloads, server config).
var serverActionTypes = map[string]bool{
	// Listener management
	"list_listeners":           true,
	"get_listener":             true,
	"delete_listener":          true,
	"add_http_listener":        true,
	"add_https_listener":       true,
	"add_dns_listener":         true,
	"add_tcp_listener":         true,
	"add_smb_listener":         true,
	"add_externalc2_listener":  true,
	"add_udc2_listener":        true,
	"add_foreign_http_listener":  true,
	"add_foreign_https_listener": true,
	"update_http_listener":       true,
	"update_https_listener":      true,
	"update_dns_listener":        true,
	"update_tcp_listener":        true,
	"update_smb_listener":        true,
	"update_externalc2_listener": true,
	"update_udc2_listener":       true,
	"update_foreign_http_listener":  true,
	"update_foreign_https_listener": true,
	// Payload operations
	"list_artifacts":             true,
	"generate_stageless_payload": true,
	"generate_stager_payload":    true,
	"download_payload":           true,
	// Server config
	"get_kill_date":         true,
	"get_c2_profile":        true,
	"get_system_info":       true,
	"get_teamserver_ip":     true,
}

// ActionRequiresBeacon returns true if the action type requires a beacon ID.
// Server-level operations (listeners, payloads, config) return false.
// The special "sleep" action also doesn't require a beacon.
func ActionRequiresBeacon(actionType string) bool {
	if serverActionTypes[actionType] {
		return false
	}
	if actionType == "sleep" {
		return false
	}
	return true
}

// ActionIsSynchronous returns true if the action returns a synchronous response
// (no task ID polling needed). All server-level operations are synchronous.
func ActionIsSynchronous(actionType string) bool {
	return serverActionTypes[actionType]
}

// WorkflowRequiresBeacon checks if any action in the workflow requires a beacon.
func WorkflowRequiresBeacon(wf *Workflow) bool {
	return actionsRequireBeacon(wf.Actions)
}

// actionsRequireBeacon recursively checks actions and their nested actions.
func actionsRequireBeacon(actions []Action) bool {
	for _, action := range actions {
		if ActionRequiresBeacon(action.Type) {
			return true
		}
		if actionsRequireBeacon(action.OnSuccess) {
			return true
		}
		if actionsRequireBeacon(action.OnFailure) {
			return true
		}
	}
	return false
}
