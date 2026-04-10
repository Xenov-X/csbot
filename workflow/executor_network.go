package workflow

import (
	"context"
	"fmt"

	csclient "github.com/xenov-x/csrest"
)

// executeNetDomain gets the current domain
func (e *Executor) executeNetDomain(ctx context.Context, client *csclient.Client, beaconID string) (string, error) {
	resp, err := client.NetDomain(ctx, beaconID)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetView lists domain hosts
func (e *Executor) executeNetView(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	domain, _ := action.Parameters["domain"].(string) // optional
	resp, err := client.NetView(ctx, beaconID, domain)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetUser lists users on a system
func (e *Executor) executeNetUser(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, _ := action.Parameters["target"].(string) // optional
	resp, err := client.NetUser(ctx, beaconID, target)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetUserDetail gets information about a specific user
func (e *Executor) executeNetUserDetail(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, _ := action.Parameters["target"].(string) // optional
	user, _ := action.Parameters["user"].(string)     // optional
	resp, err := client.NetUserDetail(ctx, beaconID, target, user)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetTime shows time for a target
func (e *Executor) executeNetTime(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, _ := action.Parameters["target"].(string) // optional
	resp, err := client.NetTime(ctx, beaconID, target)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetShare lists shares on a target
func (e *Executor) executeNetShare(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, _ := action.Parameters["target"].(string) // optional
	resp, err := client.NetShare(ctx, beaconID, target)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetSessions lists sessions on a target
func (e *Executor) executeNetSessions(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, _ := action.Parameters["target"].(string) // optional
	resp, err := client.NetSessions(ctx, beaconID, target)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetLogons lists logged in users on a target
func (e *Executor) executeNetLogons(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, _ := action.Parameters["target"].(string) // optional
	resp, err := client.NetLogons(ctx, beaconID, target)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetLocalGroup enumerates local groups on a specific system
func (e *Executor) executeNetLocalGroup(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, _ := action.Parameters["target"].(string)       // optional
	groupName, _ := action.Parameters["group_name"].(string) // optional
	resp, err := client.NetLocalGroup(ctx, beaconID, target, groupName)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetGroup enumerates groups on a domain controller
func (e *Executor) executeNetGroup(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	target, _ := action.Parameters["target"].(string)       // optional
	groupName, _ := action.Parameters["group_name"].(string) // optional
	resp, err := client.NetGroup(ctx, beaconID, target, groupName)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetDomainTrusts lists domain trusts for the specified domain
func (e *Executor) executeNetDomainTrusts(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	domain, _ := action.Parameters["domain"].(string) // optional
	resp, err := client.NetDomainTrusts(ctx, beaconID, domain)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetDomainControllers lists hosts from the Domain Controllers group on the specified domain
func (e *Executor) executeNetDomainControllers(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	domain, _ := action.Parameters["domain"].(string) // optional
	resp, err := client.NetDomainControllers(ctx, beaconID, domain)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetDcList lists domain controllers for the specified domain
func (e *Executor) executeNetDcList(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	domain, _ := action.Parameters["domain"].(string) // optional
	resp, err := client.NetDcList(ctx, beaconID, domain)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executeNetComputers lists hosts from the Domain Computers and Domain Controllers groups on the specified domain
func (e *Executor) executeNetComputers(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	domain, _ := action.Parameters["domain"].(string) // optional
	resp, err := client.NetComputers(ctx, beaconID, domain)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}

// executePortScan runs a portscan against the specified hosts
func (e *Executor) executePortScan(ctx context.Context, client *csclient.Client, beaconID string, action Action) (string, error) {
	// Extract required parameters
	targetsRaw, ok := action.Parameters["targets"]
	if !ok {
		return "", fmt.Errorf("portscan requires 'targets' parameter")
	}

	portsRaw, ok := action.Parameters["ports"]
	if !ok {
		return "", fmt.Errorf("portscan requires 'ports' parameter")
	}

	// Convert targets to []string
	var targets []string
	switch v := targetsRaw.(type) {
	case []interface{}:
		for _, t := range v {
			if str, ok := t.(string); ok {
				targets = append(targets, str)
			}
		}
	case []string:
		targets = v
	case string:
		targets = []string{v}
	default:
		return "", fmt.Errorf("targets must be a string or array of strings")
	}

	if len(targets) == 0 {
		return "", fmt.Errorf("targets must contain at least one host")
	}

	// Convert ports to []string
	var ports []string
	switch v := portsRaw.(type) {
	case []interface{}:
		for _, p := range v {
			if str, ok := p.(string); ok {
				ports = append(ports, str)
			} else if num, ok := p.(int); ok {
				ports = append(ports, fmt.Sprintf("%d", num))
			} else if num, ok := p.(float64); ok {
				ports = append(ports, fmt.Sprintf("%.0f", num))
			}
		}
	case []string:
		ports = v
	case string:
		ports = []string{v}
	case int:
		ports = []string{fmt.Sprintf("%d", v)}
	case float64:
		ports = []string{fmt.Sprintf("%.0f", v)}
	default:
		return "", fmt.Errorf("ports must be a string, number, or array")
	}

	if len(ports) == 0 {
		return "", fmt.Errorf("ports must contain at least one port")
	}

	// Extract optional parameters
	method, _ := action.Parameters["method"].(string) // optional: arp, icmp, none
	maxConnections := 0
	if mc, ok := action.Parameters["max_connections"]; ok {
		switch v := mc.(type) {
		case int:
			maxConnections = v
		case float64:
			maxConnections = int(v)
		}
	}

	resp, err := client.PortScan(ctx, beaconID, targets, ports, method, maxConnections)
	if err != nil {
		return "", err
	}
	return e.waitForOutput(ctx, client, resp.TaskID)
}
