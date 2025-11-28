# Workflow Templates

This directory contains ready-to-use workflow templates for common operational tasks and example workflows demonstrating various features.

> [!CAUTION]
> **Known Issues:**
> - Upload action (`type: upload`) currently hangs waiting for task completion. The API endpoint returns `IN_PROGRESS` indefinitely. Avoid using upload actions until resolved.
> - BOF pack action (`type: bof_pack`) has server-side issues. Use `bof_pack_custom` instead for client-side argument packing.

## Operational Templates

### 1. privilege-escalation.yaml
Attempts multiple privilege escalation techniques:
- Checks current privileges
- Attempts `getsystem` if SeImpersonatePrivilege is present
- Falls back to alternative methods if needed
- Demonstrates conditional logic with `any_of` for privilege checks

### 2. credential-harvesting.yaml
Collects credentials from target:
- LSASS dumps (requires SYSTEM or impersonated SYSTEM - uses `any_of` conditions)
- Saved credentials enumeration
- Downloads dump files
- Cleanup operations
- File system password searches

### 3. domain-recon.yaml
Active Directory environment enumeration:
- Domain information
- Domain controllers
- Domain admins and enterprise admins
- Domain users and groups
- Domain trusts
- SPN enumeration
- PowerShell-based enumeration

### 4. persistence.yaml
Establishes multiple persistence mechanisms:
- Registry run keys
- Scheduled tasks
- WMI event subscriptions (admin required)
- Verification of persistence
- Conditional execution based on privileges

### 5. parallel-recon.yaml
Fast system reconnaissance using parallel execution:
- System information
- Process list
- Network connections
- Installed software
- Services
- Users and groups
- Screenshot

All actions execute simultaneously for faster results (set `parallel: true` at workflow level).

### 6. get_system.yaml
SeImpersonate privilege escalation workflow:
- Checks for SeImpersonatePrivilege using whoami BOF
- Attempts `getsystem` if privilege exists
- Verifies elevation with `getuid`
- Post-exploitation tasks on success
- Demonstrates BOF execution with conditions

### 7. lateral-movement.yaml
Enumerates and attempts lateral movement:
- Network enumeration
- Domain computer discovery
- SMB share enumeration
- Admin share access testing
- Conditional payload deployment on success

**Note:** Upload functionality currently has issues. This template demonstrates the intended workflow pattern.

## Example Workflows

### 8. workflow.yaml
Basic workflow example demonstrating:
- BOF execution with `bof_string`
- Sequential action execution
- Simple workflow structure
- Beacon-specific targeting

### 9. workflow-interactive.yaml
Demonstrates interactive beacon selection:
- No `beacon_id` specified in YAML
- Prompts user to select from available beacons
- Shows beacon selection feature

### 10. workflow-complex.yaml
Complex workflow demonstrating:
- Conditional execution with `conditions`
- Success/failure branching with `on_success`/`on_failure`
- Multiple action types
- Nested workflows
- Action dependencies

### 11. workflow-recon.yaml
Reconnaissance workflow example:
- Screenshot capture
- System enumeration
- Process listing
- AV detection with conditional actions
- Sequential recon operations

### 12. workflow-fileops.yaml
File operation workflow demonstrating:
- File upload to beacon's CWD
- Command execution (using relative paths)
- File download
- Cleanup operations with `on_success`

**Note:** Upload currently hangs - workflow demonstrates intended usage pattern.

### 13. simple-recon.yaml
Simplified parallel reconnaissance:
- System info, processes, network, software
- Services, users, groups
- Screenshot
- Demonstrates `parallel: true` workflow setting

### 14. bof-dir.yaml
BOF execution example with typed arguments:
- Uses `bof_pack_custom` (client-side packing workaround)
- Demonstrates BOF with typed arguments (string, short)
- Directory listing BOF from CS-Situational-Awareness-BOF
- Shows argument type syntax (`z`, `s`, `i`, `b`)

## Usage

```bash
# Use a template as-is (interactive beacon selection)
./csbot -config config.yaml -workflow templates/parallel-recon.yaml

# Specify beacon in YAML to skip selection
# Edit template to add: beacon_id: "abc123"
./csbot -config config.yaml -workflow templates/domain-recon.yaml

# With command-line overrides
./csbot -host 10.0.0.1 -username operator -password pass -workflow templates/privilege-escalation.yaml -insecure

# Enable debug logging to troubleshoot
./csbot -config config.yaml -workflow templates/get_system.yaml -log-level debug

# Copy and customize templates
cp templates/credential-harvesting.yaml my-custom-workflow.yaml
# Edit my-custom-workflow.yaml with your actions
./csbot -config config.yaml -workflow my-custom-workflow.yaml
```

## Customization

Templates can be customized by:
- **Adding/removing actions** - Modify the `actions` list
- **Modifying commands** - Change `command` parameters for shell/powershell
- **Adjusting conditions** - Use `conditions`, `any_of`, or `all_of` for conditional execution
- **Adding branching** - Use `on_success`/`on_failure` for different execution paths
- **Beacon metadata conditions** - Reference beacon properties with `beacon.user`, `beacon.os`, `beacon.isAdmin`, etc.
- **Parallel execution** - Set `parallel: true` at workflow level for concurrent action execution
- **Defining variables** - Use `variables:` section to define reusable values (e.g., paths, names)
- **Variable interpolation** - Reference variables with `${variable_name}` or action outputs with `${action_name}`

## Template Features Overview

| Template | Parallel | Conditions | Branching | Beacon Metadata | BOF | PowerShell |
|----------|----------|------------|-----------|-----------------|-----|------------|
| privilege-escalation.yaml | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| credential-harvesting.yaml | ❌ | ✅ (any_of) | ✅ | ✅ | ❌ | ✅ |
| domain-recon.yaml | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| persistence.yaml | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ |
| parallel-recon.yaml | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| get_system.yaml | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ |
| lateral-movement.yaml | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| workflow-complex.yaml | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ |
| workflow-fileops.yaml | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| workflow-recon.yaml | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| simple-recon.yaml | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| bof-dir.yaml | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |

## Action Types Used in Templates

- **shell** - Execute cmd.exe commands
- **powershell** - Execute PowerShell commands using managed PowerShell
- **getuid** - Get current user context and privileges
- **getsystem** - Attempt privilege escalation to SYSTEM
- **screenshot** - Capture screenshot from beacon
- **download** - Download file from beacon to team server
- **upload** - Upload file to beacon's CWD (⚠️ currently has issues)
- **consolecommand** - Execute any CS console command (including server aliases)
- **bof_string** - Execute BOF with string arguments
- **bof_pack_custom** - Execute BOF with typed arguments (client-side packing)
- **bof_pack** - Execute BOF with typed arguments (⚠️ server-side issues)

## Condition Features

Templates demonstrate various condition patterns:

**Simple conditions (legacy AND logic):**
```yaml
conditions:
  - source: check_user
    operator: contains
    value: "SYSTEM"
```

**OR logic with `any_of`:**
```yaml
any_of:
  - source: beacon.user
    operator: contains
    value: "SYSTEM"
  - source: beacon.impersonated
    operator: contains
    value: "SYSTEM"
```

**AND logic with `all_of`:**
```yaml
all_of:
  - source: beacon.isAdmin
    operator: equals
    value: "true"
  - source: beacon.os
    operator: contains
    value: "Windows 10"
```

**Beacon metadata fields:**
- `beacon.user` - Current user
- `beacon.impersonated` - Impersonated user
- `beacon.isAdmin` - Admin/elevated status
- `beacon.computer` - Computer name
- `beacon.os` - Operating system
- `beacon.internal` - Internal IP
- `beacon.process` - Process name
- `beacon.pid` - Process ID
- `beacon.beaconArch` - Beacon architecture

See [TEMPLATE_DEV.md](../TEMPLATE_DEV.md) for complete template syntax reference.

For complete template development guide, see [TEMPLATE_DEV.md](../TEMPLATE_DEV.md).
