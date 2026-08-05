[한국어](README.md) | **English**

# 🚀 windows_diagnose

**Read-only Windows OS diagnostic tool — manage on-prem/Azure/AWS/GCP servers uniformly via Azure Arc.**

Part of the same diagnostic tool suite as `pg_diagnose` / `aks_diagnose` / `adx_diagnose` / `eh_diagnose` / `agw_diagnose` / `svcmap_diagnose` / `linux_diagnose` — strict read-only, JSON/HTML/table output, `health_score`/`summary`/`recommended_actions`.

## Recommended path — Azure Arc

This tool is designed by default to query **already-collected Azure Monitor Agent telemetry** (Log Analytics) via read-only KQL. On-prem/AWS/GCP servers can be onboarded as [Azure Arc-enabled servers](https://learn.microsoft.com/azure/azure-arc/servers/overview) (`azcmagent connect`), after which Azure Monitor Agent installs and reports telemetry just like a native Azure VM — **Arc onboarding is the prerequisite for this tool's officially supported path**.

```bash
python windows_diagnose.py --computer WIN-APP01 --workspace-id <workspace-guid> \
  --resource-id /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.HybridCompute/machines/WIN-APP01
```

`--resource-id` accepts either an Arc machine (`Microsoft.HybridCompute/machines`) or a native Azure VM (`Microsoft.Compute/virtualMachines`) — control-plane info (Arc: agent connectivity status; Azure VM: power state) is fetched automatically for either type.

## Hidden option — when Azure Arc can't be connected

For exceptional environments where Azure Arc cannot be onboarded (firewall/policy constraints), a **direct WinRM collection mode also exists internally**. It is not advertised via `--help` (not the recommended path), but works exactly as documented when specified explicitly:

```bash
# Not shown in --help, but works when specified explicitly
$env:WINDOWS_DIAGNOSE_WINRM_PASSWORD = "..."
python windows_diagnose.py --source direct --host win01.corp.local --winrm-user diag_reader --format table
```

| | `azure-monitor` (default, officially supported) | `direct` (hidden, for non-Arc environments) |
|---|---|---|
| Reads | Already-collected Azure Monitor Agent telemetry via KQL | Live PowerShell/CIM output over WinRM |
| Requires | **Azure Arc onboarding** (or Azure VM) + AMA + Log Analytics workspace | WinRM reachable (`Enable-PSRemoting`) |
| Visibility | Shown in `--help` | Hidden from `--help` (documented here only) |

## Checks

| Category | Signal |
|---|---|
| `connectivity` | Heartbeat gap (azure-monitor) or WinRM connection success (direct) |
| `cpu` | Processor / % Processor Time (or `Win32_Processor.LoadPercentage` in direct mode) |
| `memory` | Memory / % Committed Bytes In Use (or `Win32_OperatingSystem` in direct mode) |
| `disk` | LogicalDisk / % Free Space (worst drive) |
| `eventlog` | System/Application Error+Critical event count |
| `stability` | Unexpected shutdown (Kernel-Power 41 / EventLog 6008) |
| `patch` | Missing security updates (Update Management, or Windows Update Agent COM in direct mode) |
| `control_plane` | VM power state/size/OS (optional, via `--resource-id`, either mode) |

## Install

```bash
pip install -r requirements.txt
```

`--source direct` uses `pywinrm`.

## Usage

```bash
# azure-monitor mode
python windows_diagnose.py --computer WIN-APP01 --workspace-id <workspace-guid> --format table

# hidden direct mode (no Azure Arc/Azure Monitor needed)
$env:WINDOWS_DIAGNOSE_WINRM_PASSWORD = "..."
python windows_diagnose.py --source direct --host win01.corp.local --winrm-user diag_reader --format table

python windows_diagnose.py --demo --format html -o windows_demo.html
```

## Time window & history

- `--hours N` (default): relative window, e.g. `--hours 24` (1 day), `--hours 168` (1 week).
- `--start-time`/`--end-time` (ISO 8601): absolute date range, azure-monitor mode only.
- `--save-snapshot <path>`: append this run's JSON result to a JSON Lines file — combine with a scheduled task/cron to build your own trend history over time (works in either mode; direct mode cannot use `--start-time`/`--end-time` since WinRM only reflects the target's current state).

## Required inputs

- azure-monitor mode: `--computer` (Log Analytics `Computer` column) + `--workspace-id`.
- direct mode (hidden): `--host` + `--winrm-user` (password via env var).
- `--resource-id` (optional, either mode): Azure VM or Arc machine ARM resource id, for control-plane info.

If required values are omitted, the JSON output's top-level `needs_input` explains what's missing and how to discover it (Resource Graph hint + a ready-to-run reinvoke example) — the same "autonomous discovery → reinvoke" pattern used by the other tools in this suite.

## RBAC

- Log Analytics workspace: `Log Analytics Reader`
- VM/Arc machine (optional): `Reader`

## Limitations

- `Update` table requires Update Management / Azure Update Manager onboarding; otherwise reported as "not evaluated".
- Direct mode's patch check (Windows Update Agent COM search) can be slow/resource-intensive — skip it with `--skip-patch-check` when running against production servers.
