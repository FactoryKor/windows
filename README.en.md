[한국어](README.md) | **English**

# 🚀 windows_diagnose

**Read-only Windows OS diagnostic tool for Azure VM / Arc-enabled servers.**

Part of the same diagnostic tool suite as `pg_diagnose` / `aks_diagnose` / `adx_diagnose` / `eh_diagnose` / `agw_diagnose` / `svcmap_diagnose` — strict read-only, JSON/HTML/table output, `health_score`/`summary`/`recommended_actions`.

It reads **already-collected Azure Monitor Agent telemetry** (Heartbeat / Perf / Event) via read-only KQL against a Log Analytics workspace — it never issues remote commands (no WinRM/Run Command) to the target server.

## Checks

| Category | Signal |
|---|---|
| `connectivity` | Heartbeat gap (agent connectivity) |
| `cpu` | Processor / % Processor Time |
| `memory` | Memory / % Committed Bytes In Use |
| `disk` | LogicalDisk / % Free Space (worst drive) |
| `eventlog` | System/Application Error+Critical event count |
| `stability` | Unexpected shutdown (Kernel-Power 41 / EventLog 6008) |
| `patch` | Missing security updates (Update Management) |
| `control_plane` | VM power state/size/OS (optional, via `--resource-id`) |

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python windows_diagnose.py --computer WIN-APP01 --workspace-id <workspace-guid> --format table
python windows_diagnose.py --computer WIN-APP01 --workspace-id <guid> --format json --exit-code
python windows_diagnose.py --demo --format html -o windows_demo.html
```

## Required inputs

- `--computer`: value of the Log Analytics `Computer` column.
- `--workspace-id`: Log Analytics workspace GUID.
- `--resource-id` (optional): VM ARM resource id, for power state/size/OS control-plane info.

If `--workspace-id`/`--resource-id` are omitted, the JSON output's top-level `needs_input` explains what's missing and how to discover it (Resource Graph hint + a ready-to-run reinvoke example) — the same "autonomous discovery → reinvoke" pattern used by the other tools in this suite.

## RBAC

- Log Analytics workspace: `Log Analytics Reader`
- VM (optional): `Reader`

## Limitations

- Arc-enabled servers (Microsoft.HybridCompute) are not supported for control-plane lookups yet (Azure VM only). Data-plane checks (Perf/Event/Heartbeat) work the same for Arc servers.
- `Update` table requires Update Management / Azure Update Manager onboarding; otherwise reported as "not evaluated".
