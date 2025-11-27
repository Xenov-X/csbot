# Workflow Templates

This directory contains ready-to-use workflow templates for common operational tasks and example workflows demonstrating various features.

## Operational Templates

### 1. privilege-escalation.yaml
Attempts multiple privilege escalation techniques:
- Checks current privileges
- Attempts `getsystem` if SeImpersonatePrivilege is present
- Falls back to alternative methods if needed

### 2. lateral-movement.yaml
Enumerates and attempts lateral movement:
- Network enumeration
- Domain computer discovery
- SMB share enumeration
- Admin share access testing
- Payload deployment

### 3. persistence.yaml
Establishes multiple persistence mechanisms:
- Registry run keys
- Scheduled tasks
- WMI event subscriptions (admin required)
- Verification of persistence

### 4. credential-harvesting.yaml
Collects credentials from target:
- Screenshots
- LSASS dumps (admin required)
- Saved credentials
- Browser credential files
- File system password searches

### 5. domain-recon.yaml
Active Directory environment enumeration:
- Domain information
- Domain controllers
- Domain admins and enterprise admins
- Domain users and groups
- Domain trusts
- SPN enumeration

### 6. parallel-recon.yaml
Fast system reconnaissance using parallel execution:
- System information
- Process list
- Network connections
- Installed software
- Services
- Users and groups
- Screenshot

All actions execute simultaneously for faster results.

## Example Workflows

### 7. workflow.yaml
Basic workflow example demonstrating:
- BOF execution
- Sequential action execution
- Simple workflow structure

### 8. workflow-interactive.yaml
Demonstrates interactive beacon selection:
- No beacon_id specified in YAML
- Prompts user to select from available beacons
- Shows beacon selection feature

### 9. workflow-complex.yaml
Complex workflow demonstrating:
- Conditional execution
- Success/failure branching
- Multiple action types
- Nested workflows

### 10. workflow-recon.yaml
Reconnaissance workflow example:
- Screenshot capture
- System enumeration
- Process listing
- AV detection with conditional actions

### 11. workflow-fileops.yaml
File operation workflow demonstrating:
- File upload
- Command execution
- File download
- Cleanup operations

### 12. example-seimpersonate.yaml
Classic privilege escalation example:
- Checks for SeImpersonatePrivilege
- Conditionally runs exploit BOF
- Demonstrates conditional logic

## Usage

```bash
# Use a template as-is
./cs-bot -workflow templates/parallel-recon.yaml

# With custom configuration
./cs-bot -config config.yaml -workflow templates/domain-recon.yaml

# Test with dry-run mode
./cs-bot -workflow templates/privilege-escalation.yaml -dry-run

# You can also copy and modify templates
cp templates/credential-harvesting.yaml my-custom-workflow.yaml
# Edit my-custom-workflow.yaml
./cs-bot -workflow my-custom-workflow.yaml
```

## Customization

Templates can be customized by:
- Adding/removing actions
- Modifying commands and parameters
- Adjusting conditions
- Adding on_success/on_failure handlers
- Changing parallel execution mode
- Using variable interpolation with `${action_name}`

## Template Features Demonstrated

| Template | Parallel | Conditions | Branching | File Ops | Variables |
|----------|----------|------------|-----------|----------|-----------|
| privilege-escalation.yaml | ❌ | ✅ | ✅ | ❌ | ❌ |
| lateral-movement.yaml | ❌ | ❌ | ✅ | ✅ | ❌ |
| persistence.yaml | ❌ | ✅ | ✅ | ❌ | ❌ |
| credential-harvesting.yaml | ❌ | ❌ | ✅ | ✅ | ❌ |
| domain-recon.yaml | ❌ | ❌ | ❌ | ❌ | ❌ |
| parallel-recon.yaml | ✅ | ❌ | ❌ | ❌ | ❌ |
| workflow-complex.yaml | ❌ | ✅ | ✅ | ❌ | ❌ |
| workflow-fileops.yaml | ❌ | ❌ | ✅ | ✅ | ❌ |
| workflow-recon.yaml | ❌ | ✅ | ✅ | ❌ | ❌ |
| example-seimpersonate.yaml | ❌ | ✅ | ✅ | ❌ | ❌ |

## Security Note

These templates demonstrate operational capabilities for authorized penetration testing. Ensure you have:
- ✅ Explicit written authorization
- ✅ Understanding of each action's impact
- ✅ Tested workflows in safe environment
- ✅ Proper handling of sensitive output

Always use `--dry-run` first to preview actions before execution.
