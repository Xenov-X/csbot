# Test Workflows

9-phase test suite covering all 150 csbot action types. Each phase is designed to run independently with increasing privilege and risk requirements.

## Prerequisites

- Cobalt Strike team server with REST API enabled
- `config.yaml` configured with valid credentials (or use env vars / CLI flags)

## Execution Order

Run phases in order. Phase 1 requires no beacon; phases 2-9 require an active beacon.

| Phase | File | Beacon | Privileges | Risk | Actions Tested |
|-------|------|--------|------------|------|----------------|
| 1 | `phase1-server-ops.yaml` | None | N/A | LOW | Listener CRUD, payload generation, server config |
| 2 | `phase2-basic-beacon.yaml` | Any | Standard | LOW | Identity, file ops, shell, PS, screenshot, conditions |
| 3 | `phase3-credentials.yaml` | Any | Admin/SYSTEM | MED | Tokens, Kerberos, hashdump, mimikatz, chromedump |
| 4 | `phase4-network-recon.yaml` | Domain-joined | Standard | LOW | net_* commands, portscan, registry queries |
| 5 | `phase5-tunneling.yaml` | Any | Admin | MED | SOCKS4/5, rportfwd, browser pivot, link, SSH |
| 6 | `phase6-execution.yaml` | Any | Standard | MED | run, powerpick, execute_assembly, BOFs |
| 7 | `phase7-spawn-inject.yaml` | Any | Admin | HIGH | spawn_beacon, inject, PtH, DLL injection |
| 8 | `phase8-beacon-config.yaml` | Any | Standard | MED | sleep, spawnto, PPID, blockdlls, beacon gate |
| 9 | `phase9-capture.yaml` | Any | Standard | MED | keylogger, screenwatch, clipboard, screenshot |

## Running a Phase

```bash
# Dry-run first (validates without executing)
./csbot -config config.yaml -workflow templates/tests/phase1-server-ops.yaml -dry-run

# Execute (Phase 1 - no beacon needed)
./csbot -config config.yaml -workflow templates/tests/phase1-server-ops.yaml

# Execute (Phases 2-9 - will prompt for beacon selection)
./csbot -config config.yaml -workflow templates/tests/phase2-basic-beacon.yaml

# With debug logging
./csbot -config config.yaml -workflow templates/tests/phase2-basic-beacon.yaml -log-level debug
```

## Commented-Out Actions

Many actions in phases 3-9 are commented out because they require:
- Valid lab credentials (make_token, run_as, ssh)
- Specific PIDs (steal_token, inject_*, run_under)
- Specific files on the operator machine (BOFs, assemblies, DLLs, shellcode)
- A second target host (link_smb, remote_exec, jump)
- Active job IDs (job_stop)

Uncomment and fill in the placeholders for your lab environment before running.

## Action Coverage

**Uncommented (run by default):** ~90 actions across all phases
**Commented (need lab-specific values):** ~60 actions with `<REPLACE_WITH_*>` placeholders

Together they cover all 150 action types.
