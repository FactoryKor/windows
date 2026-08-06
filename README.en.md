[한국어](README.md) | **English**

# 🚀 windows_diagnose

**Read-only Windows OS diagnostic tool — manage on-prem/Azure/AWS/GCP servers uniformly via Azure Arc**

Diagnoses CPU/memory/disk/agent-connectivity/event-log/patch status on a target Windows server. Part
of the same diagnostic tool suite as `pg_diagnose` / `aks_diagnose` / `adx_diagnose` / `eh_diagnose` /
`agw_diagnose` / `svcmap_diagnose` / `linux_diagnose` — following the same design philosophy (strict
read-only, JSON/HTML/table output, `health_score`/`summary`/`recommended_actions`).

## ✅ Recommended usage — Azure Arc onboarding

By default, this tool is designed to query **already-collected Azure Monitor Agent telemetry**
(Log Analytics) via read-only KQL. On-prem/AWS/GCP servers can be onboarded as
[Azure Arc-enabled servers](https://learn.microsoft.com/azure/azure-arc/servers/overview)
(`azcmagent connect`), after which they get Azure Monitor Agent installed and can send telemetry to a
Log Analytics workspace just like a native Azure VM — in other words, **Arc onboarding is the
prerequisite for this tool's officially supported path**.

```bash
python windows_diagnose.py --computer WIN-APP01 --workspace-id <workspace-guid> \
  --resource-id /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.HybridCompute/machines/WIN-APP01
```

Passing either an Arc machine (`Microsoft.HybridCompute/machines`) or a native Azure VM
(`Microsoft.Compute/virtualMachines`) resource ID to `--resource-id` automatically fetches
control-plane info for both types (Arc: agent connectivity status; Azure VM: power state).

## 🔒 Hidden option — when Azure Arc can't be onboarded

For exceptional environments (firewall/policy/organizational constraints) where Azure Arc cannot be
onboarded, **a `--source direct` option that connects and collects directly via WinRM is also
supported internally**. This path is not recommended for general users and therefore doesn't appear
in `--help`, but it works exactly as documented when specified explicitly:

```bash
# Not shown in --help, but works when specified explicitly
$env:WINDOWS_DIAGNOSE_WINRM_PASSWORD = "..."
python windows_diagnose.py --source direct --host WIN-ONPREM01 --winrm-user diag_reader --format table
```

| | `--source azure-monitor` (default, officially supported) | `--source direct` (hidden option, for non-Arc environments) |
|---|---|---|
| What it reads | Already-collected Azure Monitor Agent telemetry (Log Analytics) | Live results of PowerShell/CIM commands run over WinRM |
| Requirements | **Azure Arc onboarding** (or Azure VM) + Azure Monitor Agent + Log Analytics workspace | WinRM reachable (`Enable-PSRemoting`) |
| Visibility | Shown in `--help` (recommended path) | Hidden from `--help` (documented here only) |
| Server impact | None (query only) | None (only read-only CIM/Get-WinEvent commands; no new agent installed via WinRM) |

For the full option list (`--winrm-user`, `--winrm-password-env`, `--winrm-transport`,
`--winrm-use-ssl`, `--winrm-cert-validation`, `--skip-patch-check`, etc.), see "Data sources" below.

- 👉 Diagnoses CPU / memory / disk free space / agent (or WinRM) connectivity / event log errors /
  unexpected restarts / patch compliance.
- 👉 Supports Azure SRE Agent and MCP Tool integration.
- 👉 When `--resource-id` is given (Azure VM or Arc machine, common to both collection modes),
  control-plane info is also fetched.

Checks:

| 📋 Category | 📋 Category |
|---|---|
| Agent (or WinRM) connectivity | CPU usage |
| Memory usage | Disk free space |
| Event log Error/Critical count | Unexpected shutdown/restart |
| Missing security updates | VM/Arc machine connectivity·power state, size, OS version (optional, ARM) |
| Stopped Automatic-start services (direct mode only) | Installed Windows Server roles/features (direct mode only, informational) |
| OS EOL lifecycle + installed EOL program detection (direct mode only) | Recommended management tools (Azure Arc/Defender/PowerShell 7, etc.) installed? (direct mode only) |

---

## Data sources

### `--source azure-monitor` (all read-only KQL queries / ARM lookups)

| # | Source | What it reads | Table/query |
|---|------|------------|------|
| 1 | **Heartbeat** | Agent connectivity (last heartbeat gap) | `Heartbeat` |
| 2 | **Perf** | CPU/memory/disk usage | `Perf` (`Processor`, `Memory`, `LogicalDisk`) |
| 3 | **Event** | System/Application event log Error/Critical, unexpected shutdown | `Event` (EventLevelName, EventID 41/6008) |
| 4 | **Update** | Patch compliance (when Update Management is enabled) | `Update` |
| 5 | **ARM (optional)** | VM or Arc machine connectivity/power state/size/OS version (control plane) | `azure-mgmt-compute` (Azure VM) or `azure-mgmt-hybridcompute` (Arc) |

`--computer` (the Log Analytics `Computer` column value) and `--workspace-id` (Log Analytics
workspace GUID) are **required**.

```text
   --computer + --workspace-id ──▶ Heartbeat/Perf/Event/Update KQL (data plane)
   --resource-id (optional, Azure VM or Arc machine) ──▶ azure-mgmt-compute or
                                        azure-mgmt-hybridcompute instanceView (control plane)
                                    └─▶ merge → OS diagnostic report
```

### `--source direct` (hidden option — direct WinRM connection when Azure Arc isn't available)

| # | Source | What it reads | Command |
|---|------|------------|------|
| 1 | CPU | Average processor load | `Get-CimInstance Win32_Processor` (`LoadPercentage`) |
| 2 | Memory | Usage vs. total | `Get-CimInstance Win32_OperatingSystem` (`TotalVisibleMemorySize`/`FreePhysicalMemory`) |
| 3 | Disk | Free space per drive | `Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"` |
| 4 | Event log | System/Application Error/Critical count | `Get-WinEvent -FilterHashtable` (Level 1,2) |
| 5 | Unexpected shutdown | Kernel-Power(41)/EventLog(6008) | `Get-WinEvent -FilterHashtable` (Id 41,6008) |
| 6 | Patch | Pending security update count (best-effort) | Windows Update Agent COM (`Microsoft.Update.Session`, no extra module needed) |
| 7 | Services | Automatic-start services that are currently stopped | `Get-CimInstance Win32_Service -Filter "StartMode='Auto' and State!='Running'"` |
| 8 | Roles/features | Installed Windows Server roles/features (informational, Server only) | `Get-WindowsFeature` (ServerManager module; silently skipped on client OS) |

`--host` (falls back to `--computer` if omitted) and `--winrm-user` are **required**. Works even
without any Azure Monitor/Log Analytics workspace at all — this is the core of on-prem/AWS/GCP
server support.

**Same philosophy as credential separation**: the WinRM password is never accepted as a CLI
argument — it's read from the environment variable named by `--winrm-password-env` (default
`WINDOWS_DIAGNOSE_WINRM_PASSWORD`), or prompted interactively in a terminal. Adjust
`--winrm-transport {ntlm(default),kerberos,credssp,basic}` and `--winrm-use-ssl` (HTTPS/5986) to
match your environment.

**Security (certificate validation)**: the default is `--winrm-cert-validation validate`. Setting
it to `ignore` (self-signed test environments only, MITM risk) surfaces a security warning finding
in the report.

```text
   --host + --winrm-user (+ password) ──▶ WinRM connection
                                          └─▶ read-only PowerShell (CIM/Get-WinEvent, etc.) → OS diagnostic report
   --resource-id (optional, Azure VM or Arc machine) ──▶ azure-mgmt-compute/azure-mgmt-hybridcompute (control plane)
```

---

## ⚡ Server load from `--source direct`

Since direct mode runs commands on the target server, understanding the load impact matters.
Bottom line: **each run executes 5 short CIM/event queries sequentially (mostly tens to hundreds of
ms) — it is not a continuously polling monitoring agent.**

| Command | Load level | Notes |
|---|---|---|
| `Get-CimInstance Win32_Processor` (CPU) | Very low | Single WMI snapshot query |
| `Get-CimInstance Win32_OperatingSystem` (memory) | Very low | Single WMI snapshot query |
| `Get-CimInstance Win32_LogicalDisk` (disk) | Very low | Single WMI snapshot query |
| `Get-WinEvent -FilterHashtable` (event log) | Low–moderate | Filtering happens at the provider, so it's efficient, but can take longer if the window has a very large number of events |
| Windows Update Agent COM `Search()` (patch check) | **Moderate–high** | Queries WSUS/Windows Update **over the network** for update metadata, so it's much slower than the other commands (can take tens of seconds or more) and briefly uses CPU while searching |

The heaviest item is the **patch check (Windows Update Agent search)**. If you want to avoid this
overhead on repeated diagnostics in production, skip it with `--skip-patch-check`:

```bash
python windows_diagnose.py --source direct --host WIN-ONPREM01 --winrm-user diag_reader --skip-patch-check
```

All other commands besides the patch check are single WMI/event-log snapshot queries, so their
impact on the target server is negligible.

---

## ⚙️ Prerequisites

**When using MCP server / Azure SRE Agent**
- No separate install is needed — this tool is already installed as a pip package in the MCP server container, and the required credentials (managed identity or `WINDOWS_DIAGNOSE_WINRM_PASSWORD`) are already configured there. Just call the `diagnose_windows_os` tool from the SRE Agent.

**When running standalone**
- Python 3.10+
- For direct mode (WinRM), WinRM must be enabled on the target Windows server (`Enable-PSRemoting -Force`). azure-monitor mode needs `az login` (locally) or a managed identity.

---

## ⚙️ Installation & Execution

**When using MCP server / Azure SRE Agent**, no installation is needed — calling the tool from the SRE Agent portal runs it inside the MCP server.

**When running standalone**:

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

`--source direct` uses `pywinrm`. WinRM must be enabled on the target Windows server
(`Enable-PSRemoting -Force`).

> [!TIP]
> **Windows note.** Set `$env:PYTHONIOENCODING="utf-8"` before running (prevents `UnicodeEncodeError`
> in the table renderer).

---

## 🧰 Usage

```bash
# [azure-monitor] basic diagnosis (table)
python windows_diagnose.py --computer WIN-APP01 --workspace-id <workspace-guid>

# [azure-monitor] including VM control plane (power state/size)
python windows_diagnose.py --computer WIN-APP01 --workspace-id <workspace-guid> \
  --resource-id /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/WIN-APP01

# [direct] diagnose directly over WinRM, no Azure Monitor needed (on-prem/AWS/GCP, etc.)
$env:WINDOWS_DIAGNOSE_WINRM_PASSWORD = "..."
python windows_diagnose.py --source direct --host WIN-ONPREM01 --winrm-user diag_reader --format table

# [direct] HTTPS(5986) + Kerberos
python windows_diagnose.py --source direct --host win01.corp.local --winrm-user diag_reader@CORP.LOCAL \
  --winrm-transport kerberos --winrm-use-ssl

# adjust thresholds (both modes)
python windows_diagnose.py --computer WIN-APP01 --workspace-id <guid> \
  --cpu-warn 75 --cpu-crit 90 --disk-free-warn 20 --disk-free-crit 10

# JSON output + exit code for CI
python windows_diagnose.py --computer WIN-APP01 --workspace-id <guid> --format json --exit-code

# save an HTML report to a file
python windows_diagnose.py --computer WIN-APP01 --workspace-id <guid> --format html -o windows_report.html

# preview with demo data (no connection)
python windows_diagnose.py --demo --format table
```

---

## 🧰 Time-window selection & history

**You can choose a period like "the last week" or "yesterday"** — the azure-monitor mode supports
two approaches.

| Approach | Example | Notes |
|---|---|---|
| Relative `--hours` (default) | `--hours 24` (1 day), `--hours 168` (1 week), `--hours 720` (30 days) | Always "N hours ago until now" |
| Absolute `--start-time`/`--end-time` | `--start-time 2026-07-28T00:00:00Z --end-time 2026-07-30T00:00:00Z` | Pin down an exact date range (e.g., Mon–Wed of last week) |

```bash
# query a specific 3-day window from last week
python windows_diagnose.py --computer WIN-APP01 --workspace-id <guid> \
  --start-time 2026-07-28T00:00:00Z --end-time 2026-07-31T00:00:00Z --format html -o last_week.html
```

**Direct mode (WinRM) can only query the target server's "right now" state, so past-date queries
aren't possible** (using it together with `--start-time`/`--end-time` returns an error). Instead,
you can use **`--save-snapshot <path>`** to append each run's results to a JSON Lines file — running
this periodically via Task Scheduler/cron (e.g., hourly) lets you build your own time-series history
for later comparison/trend analysis.

```bash
# register in Task Scheduler to run hourly → builds its own history
python windows_diagnose.py --source direct --host WIN-ONPREM01 --winrm-user diag_reader `
  --format json --save-snapshot C:\diag-history\win-onprem01.jsonl
```

---

## 🧰 Diagnostic Rules

| Category | Signal | Warning | Critical | Formula / Notes |
|----------|--------|---------|----------|---------------|
| `connectivity` | Heartbeat gap | ≥ `--heartbeat-warn-min` (default 15 min) | ≥ `--heartbeat-crit-min` (default 60 min) | `now - last_heartbeat` |
| `cpu` | Average % Processor Time | ≥ `--cpu-warn` (default 80%) | ≥ `--cpu-crit` (default 95%) | Average over the `Perf` window |
| `memory` | Average % Committed Bytes In Use | ≥ `--mem-warn` (default 85%) | ≥ `--mem-crit` (default 95%) | Average over the `Perf` window |
| `disk` | Minimum % Free Space (per drive) | ≤ `--disk-free-warn` (default 15%) | ≤ `--disk-free-crit` (default 5%) | Drive with the least free space |
| `eventlog` | Error/Critical event count | ≥ `--log-err-warn` (default 10) | ≥ `--log-err-crit` (default 50) | Total within the window |
| `stability` | Kernel-Power(41)/EventLog(6008) | — | 1+ = critical | Unexpected shutdown/restart |
| `patch` | Missing security update count | 1+ | 10+ | `Update` table (Update Management) |
| `services` | Stopped Automatic-start services (direct mode only) | ≥ `--services-warn` (default 1) | ≥ `--services-crit` (default 5) | Count of `Win32_Service` filter results |
| `roles_features` | Installed roles/features (direct mode only, informational) | — | — | Always info (not treated as a problem) |
| `os_lifecycle` | OS EOL lifecycle (direct mode only) | ≤ `--eol-warn-days` (default 180) until EOL | Already past EOL | Embedded lifecycle table lookup |
| `win11_readiness` | Windows 11 hardware readiness (Windows 10 targets only, direct mode only) | TPM/Secure Boot not met | — | TPM 2.0/Secure Boot check (informational) |
| `software_eol` | Known EOL programs installed (direct mode only) | 1+ found | — | .NET/SQL Server/Java, etc. pattern match |
| `recommended_software` | Recommended management tool missing (direct mode only) | — | — | Always info (not treated as a problem) |
| `control_plane` | VM power state | — | Deallocated/Stopped = critical | ARM instanceView (optional) |

Every item is shown as **"not evaluated"** rather than hidden when data is unavailable (same
report-completeness philosophy as the other tools).

---

## 🧰 Output Schema

Uses the same `category` + `severity` schema as the other tools, with top-level
`summary`/`health_score`/`severity_counts`/`recommended_actions`/`needs_input`.

| Mode | Content |
|---|---|
| `--format table` (default) | Human-readable text table |
| `--format json` | `checks[]`-schema JSON (for SRE Agent / MCP integration) |
| `--format html` | Summary cards + diagnostic table (`-o` to save to a file) |

- `--exit-code` returns a CI-friendly exit code (critical=2, warning=1, otherwise 0)

### Sample output

```json
{
  "tool": "windows_diagnose",
  "version": "1.0.0",
  "computer": "WIN-APP01",
  "window": "last 24h",
  "checks": [
    {
      "category": "disk",
      "severity": "critical",
      "title": "Low disk free space: C:",
      "detail": "Free space 3.2% (critical threshold ≤ 5.0%).",
      "recommendation": "Clean up unnecessary files/logs on the C: drive or expand the volume."
    }
  ],
  "health_score": 62,
  "severity_counts": {"critical": 1, "warning": 1, "info": 0, "ok": 5},
  "summary": "Health score 62/100 (critical). WIN-APP01, last 24h (critical 1, warning 1, info 0).",
  "worst_severity": "critical"
}
```

---

## 🧰 Autonomous discovery → reinvoke loop (needs_input)

In `--source azure-monitor`, a missing `--workspace-id` is flagged as required, and a missing
`--resource-id` (in either mode) is flagged as optional — the top-level `needs_input` in the result
JSON is populated with the needed values, a `discovery_hint` (an example Resource Graph KQL query),
and a `reinvoke_example` (an example reinvocation command). `--source direct` may target on-prem/
AWS/GCP hosts where a resource_id might not even exist, so it is **never forced** (you can still pass
`--resource-id` directly if you know it). Azure SRE Agent can use this to resolve the value and
reinvoke the tool.

---

## 🧰 MCP / Azure SRE Agent integration

Registered in `mcp_server.py` as the `diagnose_windows_os` tool (same pattern as pg/aks/adx/eh/agw/
svcmap — a common `_run()` wrapper turns timeouts/failures into structured JSON). The `source`
parameter selects `azure-monitor`/`direct`; when `direct`, `host`/`winrm_user` are passed (the
password is never passed as an MCP argument — the MCP container must have the
`WINDOWS_DIAGNOSE_WINRM_PASSWORD` environment variable set in advance).

Grant the Managed Identity the following RBAC (when using azure-monitor mode and/or the control plane):

- **Log Analytics workspace**: `Log Analytics Reader` (Perf/Event/Heartbeat/Update queries)
- **VM (optional, when using `--resource-id`)**: `Reader` (instanceView query)

`direct` mode is independent of Azure permissions — it only needs an account that can connect to the
target server over WinRM (read-only permissions recommended).

---

## Limitations / Accuracy notes

- Arc-enabled servers (Microsoft.HybridCompute) don't support control-plane queries in the current
  version (only Azure VM is supported). The data plane (Perf/Event/Heartbeat, or direct WinRM
  collection) works the same for Arc servers.
- `--source azure-monitor`: the `Update` table is only populated when Update Management (or Azure
  Update Manager) onboarding is done. It shows as "not evaluated" when not onboarded.
- `--source direct`: the Windows Update Agent COM search can be slow depending on WSUS/internet
  connectivity, and silently falls back to "not evaluated" on failure (the diagnosis itself doesn't
  stop).
- No remote command execution (Run Command, etc.) is used — azure-monitor mode only reads
  already-collected telemetry, and direct mode only runs read-only CIM/Get-WinEvent commands.


---

## License

This project is licensed under the [MIT License](LICENSE).
