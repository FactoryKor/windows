#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
windows_diagnose.py — Windows OS read-only diagnostic CLI.
Supports **two independent collection modes** so it works whether or not the
target uses Azure Monitor — on-premises, AWS, GCP, or any other environment:

  --source azure-monitor (default)  이미 수집돼 있는 Azure Monitor Agent 원격
                                    측정(Log Analytics)을 읽기 전용 KQL로 조회.
                                    Azure VM / Arc-enabled server 전용.
  --source direct                   WinRM으로 대상 호스트에 직접 접속해 PowerShell/
                                    CIM 명령으로 실시간 수집. Azure Monitor가
                                    전혀 없는 온프레미스·AWS·GCP 등 모든 환경에서 동작.

Part of the Azure diagnostic tool suite (pg / aks / adx / eh / agw / svcmap).
Design mirrors svcmap_diagnose: strict READ-ONLY, JSON/HTML/table output,
health_score / summary / recommended_actions for the SRE Agent / MCP path.

데이터 소스
-----------
[azure-monitor 모드] 모두 읽기 전용 KQL 질의, Log Analytics workspace
  1. Heartbeat     : 에이전트 연결 상태(마지막 하트비트 간격)
  2. Perf          : CPU(Processor/% Processor Time), 메모리(Memory/% Committed
                     Bytes In Use), 디스크 여유공간(LogicalDisk/% Free Space)
  3. Event         : System/Application 이벤트 로그의 Error/Critical 발생 건수,
                     예기치 않은 종료(Kernel-Power 41 / EventLog 6008)
  4. Update        : Update Management 패치 준수 상태(선택, 미설치 시 미평가)

[direct 모드] WinRM으로 접속해 읽기 전용 PowerShell/CIM 명령만 실행(서버 미변경)
  1. Win32_Processor          CPU 사용률(LoadPercentage)
  2. Win32_OperatingSystem    메모리 사용률(TotalVisibleMemorySize/FreePhysicalMemory)
  3. Win32_LogicalDisk        디스크 여유공간(DriveType=3)
  4. Get-WinEvent              System/Application Error/Critical 건수,
                              예기치 않은 종료(Id 41/6008)
  5. Windows Update Agent COM  보안 업데이트 대기 건수(최선다, 느릴 수 있음/타임아웃 가능)

두 모드 모두 (선택) ARM 제어 평면: azure-mgmt-compute로 VM 전원 상태/크기/OS 버전 조회
                                (--resource-id 지정 시, direct 모드에서도 Azure/Arc VM이면 사용 가능)

모든 동작은 읽기 전용이며 어떤 리소스도 변경하지 않는다.

Windows note: set  $env:PYTHONIOENCODING="utf-8"  before running if the table
renderer raises UnicodeEncodeError.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

TOOL_NAME = "windows_diagnose"
TOOL_VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# Thresholds (single source of truth; overridable via CLI)
# --------------------------------------------------------------------------- #
DEFAULTS = {
    "cpu_warn": 80.0, "cpu_crit": 95.0,              # avg % Processor Time
    "mem_warn": 85.0, "mem_crit": 95.0,              # avg % Committed Bytes In Use
    "disk_free_warn": 15.0, "disk_free_crit": 5.0,   # % Free Space (lower = worse)
    "heartbeat_warn_min": 15, "heartbeat_crit_min": 60,
    "log_err_warn": 10, "log_err_crit": 50,          # Error/Critical events over window
    "services_warn": 1, "services_crit": 5,          # stopped Automatic-start services
    "eol_warn_days": 180,                            # OS EOL이 이 일수 이내면 warning
}

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
SEV_LABEL_KO = {"critical": "위험", "warning": "주의", "info": "정보", "ok": "양호"}

# --------------------------------------------------------------------------- #
# OS 수명주기 표(참고용, 주기적 갱신 필요) — windows_upgrade_diagnose에서 통합됨. 순서 중요(구체적인 패턴 먼저 매칭)
# --------------------------------------------------------------------------- #
OS_LIFECYCLE: list[dict[str, Any]] = [
    {"match": "Windows Server 2012 R2", "name": "Windows Server 2012 R2",
     "eol": date(2023, 10, 10), "esm_eol": date(2026, 10, 13)},
    {"match": "Windows Server 2012", "name": "Windows Server 2012",
     "eol": date(2023, 10, 10), "esm_eol": None},
    {"match": "Windows Server 2016", "name": "Windows Server 2016",
     "eol": date(2027, 1, 12), "esm_eol": None},
    {"match": "Windows Server 2019", "name": "Windows Server 2019",
     "eol": date(2029, 1, 9), "esm_eol": None},
    {"match": "Windows Server 2022", "name": "Windows Server 2022",
     "eol": date(2031, 10, 14), "esm_eol": None},
    {"match": "Windows Server 2025", "name": "Windows Server 2025",
     "eol": date(2034, 10, 10), "esm_eol": None},
    {"match": "Windows 11", "name": "Windows 11 (에디션/빌드별 별도 확인 필요)",
     "eol": date(2027, 10, 12), "esm_eol": None},
    {"match": "Windows 10", "name": "Windows 10",
     "eol": date(2025, 10, 14), "esm_eol": date(2028, 10, 10)},
]

KNOWN_EOL_SOFTWARE: list[dict[str, str]] = [
    {"pattern": r"microsoft \.net framework 4\.[0-5]([^0-9]|$)", "name": ".NET Framework 4.0~4.5.2",
     "eol": "2022-04-26", "note": ".NET Framework 4.8 이상 또는 .NET(Core) 최신 LTS로 마이그레이션하세요."},
    {"pattern": r"sql server 2012", "name": "SQL Server 2012", "eol": "2022-07-12",
     "note": "SQL Server 2019/2022로 업그레이드하세요(mssql_diagnose로 세부 진단 가능)."},
    {"pattern": r"sql server 2014", "name": "SQL Server 2014", "eol": "2024-07-09",
     "note": "SQL Server 2019/2022로 업그레이드하세요(mssql_diagnose로 세부 진단 가능)."},
    {"pattern": r"^java (7|6|se 6|se 7)\b|jre 7|jre 6", "name": "Java 6/7(Oracle)", "eol": "2022-07-01",
     "note": "Java 11/17/21 LTS로 업그레이드하세요."},
    {"pattern": r"python 2\.", "name": "Python 2.x", "eol": "2020-01-01",
     "note": "Python 3.x로 마이그레이션하세요."},
    {"pattern": r"internet explorer", "name": "Internet Explorer", "eol": "2022-06-15",
     "note": "Microsoft Edge(IE 모드 포함)로 전환하세요."},
    {"pattern": r"visual c\+\+ 2008|visual c\+\+ 2010", "name": "구버전 Visual C++ Redistributable",
     "eol": "-", "note": "최신 Visual C++ Redistributable로 교체를 검토하세요."},
]

RECOMMENDED_SOFTWARE: list[dict[str, str]] = [
    {"check": "Azure Connected Machine 에이전트(Azure Arc)", "pattern": r"azure connected machine agent",
     "reason": "Azure Arc로 온보딩하면 patch/정책/모니터링을 중앙에서 통합 관리할 수 있습니다"
              "(azure-monitor 모드의 전제 조건이기도 합니다)."},
    {"check": "Microsoft Defender(또는 동급 엔드포인트 보호)", "pattern": r"defender|endpoint protection",
     "reason": "엔드포인트 보호가 없으면 멀웨어/랜섬웨어에 취약합니다."},
    {"check": "PowerShell 7 이상", "pattern": r"powershell 7",
     "reason": "최신 PowerShell은 성능/보안 패치가 지속 제공됩니다(Windows PowerShell 5.1은 유지보수 모드)."},
    {"check": "백업 에이전트(Azure Backup/MARS 등)", "pattern": r"microsoft azure recovery|azure backup|mars agent",
     "reason": "정기 백업 없이는 장애/랜섬웨어 발생 시 복구가 불가능합니다."},
]


# --------------------------------------------------------------------------- #
# Result model (shape shared with the rest of the suite)
# --------------------------------------------------------------------------- #
@dataclass
class Check:
    category: str
    severity: str  # critical | warning | info | ok
    title: str
    detail: str
    recommendation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    tool: str = TOOL_NAME
    version: str = TOOL_VERSION
    collection_mode: str = "azure-monitor"  # azure-monitor | direct
    computer: str = ""
    generated_at: str = ""
    window: str = ""
    sources: list[str] = field(default_factory=list)
    vm_info: dict[str, Any] = field(default_factory=dict)
    checks: list[Check] = field(default_factory=list)
    needs_input: list[dict[str, str]] = field(default_factory=list)

    def add(self, category: str, severity: str, title: str, detail: str,
            evidence: Optional[dict[str, Any]] = None, recommendation: str = "") -> None:
        self.checks.append(Check(category, severity, title, detail,
                                 recommendation, evidence or {}))

    def request_input(self, parameter: str, reason: str, discovery_hint: str,
                      reinvoke_example: str) -> None:
        """자율 발견 루프: 도구가 스스로 알아낼 수 없는 값을 SRE Agent에게 요청한다."""
        self.needs_input.append({"parameter": parameter, "reason": reason,
                                 "discovery_hint": discovery_hint,
                                 "reinvoke_example": reinvoke_example})

    def worst_severity(self) -> str:
        if not self.checks:
            return "ok"
        return min((c.severity for c in self.checks), key=lambda s: SEVERITY_ORDER[s])

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "warning": 0, "info": 0, "ok": 0}
        for c in self.checks:
            if c.severity in counts:
                counts[c.severity] += 1
        return counts

    def health_score(self) -> int:
        penalty = {"critical": 25, "warning": 8, "info": 0, "ok": 0}
        score = 100 - sum(penalty.get(c.severity, 0) for c in self.checks)
        return max(0, min(100, score))

    def recommended_actions(self) -> list[dict[str, str]]:
        seen: set[str] = set()
        actions: list[dict[str, str]] = []
        for c in sorted(self.checks, key=lambda x: SEVERITY_ORDER[x.severity]):
            if not c.recommendation or c.recommendation in seen:
                continue
            seen.add(c.recommendation)
            actions.append({"severity": c.severity, "category": c.category,
                            "title": c.title, "action": c.recommendation})
        return actions

    def summary_text(self) -> str:
        c = self.severity_counts()
        return (f"건강 점수 {self.health_score()}/100 "
                f"({SEV_LABEL_KO.get(self.worst_severity(), self.worst_severity())}). "
                f"{self.computer or '대상 서버'}, {self.window} "
                f"(위험 {c['critical']}, 주의 {c['warning']}, 정보 {c['info']}).")


# --------------------------------------------------------------------------- #
# 조회 기간 — 상대 시간(--hours, 기본: "마지막 N시간") 또는 절대 날짜범위
# (--start-time/--end-time, 예: "지난주 월요일~수요일")을 선택할 수 있다. azure-monitor 모드에만 적용된다
# (direct 모드는 항상 현재 시점의 라이브 명령이라 과거 날짜를 조회할 수 없음).
# --------------------------------------------------------------------------- #
@dataclass
class TimeWindow:
    hours: int = 24
    start: Optional[datetime] = None
    end: Optional[datetime] = None

    def kql_filter(self) -> str:
        if self.start:
            end_dt = self.end or datetime.now(timezone.utc)
            return (f'TimeGenerated between (datetime({self.start.isoformat()}) .. '
                   f'datetime({end_dt.isoformat()}))')
        return f"TimeGenerated > ago({self.hours}h)"

    def timespan(self):
        if self.start:
            return (self.start, self.end or datetime.now(timezone.utc))
        return timedelta(hours=self.hours)

    def label(self) -> str:
        if self.start:
            end_dt = self.end or datetime.now(timezone.utc)
            return f"{self.start.isoformat()} ~ {end_dt.isoformat()}"
        return f"last {self.hours}h"


# --------------------------------------------------------------------------- #
# KQL (read-only queries against Log Analytics)
# --------------------------------------------------------------------------- #
_HEARTBEAT_KQL = """
Heartbeat
| where Computer =~ "{computer}"
| where {time_filter}
| summarize last_heartbeat = max(TimeGenerated), samples = count()
"""

_PERF_KQL = """
Perf
| where Computer =~ "{computer}"
| where {time_filter}
| where ObjectName == "{obj}" and CounterName == "{counter}"
{instance_clause}
| summarize avg_val = avg(CounterValue), max_val = max(CounterValue) by InstanceName
| order by avg_val desc
"""

_EVENT_ERR_KQL = """
Event
| where Computer =~ "{computer}"
| where {time_filter}
| where EventLevelName in ("Error", "Critical")
| summarize count() by EventLog, EventLevelName
"""

_EVENT_SHUTDOWN_KQL = """
Event
| where Computer =~ "{computer}"
| where {time_filter}
| where EventID in (41, 6008)
| summarize cnt = count(), sample = any(RenderedDescription)
"""

_UPDATE_KQL = """
Update
| where Computer =~ "{computer}"
| where {time_filter}
| where UpdateState == "Needed" and Optional == false
| summarize count() by Classification
"""

RID_PARSE = re.compile(
    r"^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/"
    r"Microsoft\.Compute/virtualMachines/([^/]+)$", re.IGNORECASE)
# Azure Arc-enabled server(Microsoft.HybridCompute) — 온프레미스/AWS/GCP 머신을 Arc로
# 온보딩하면 이 리소스 유형으로 ARM에 등록된다(권장 경로 — azure-monitor 모드 + 이 resource_id).
RID_PARSE_ARC = re.compile(
    r"^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/"
    r"Microsoft\.HybridCompute/machines/([^/]+)$", re.IGNORECASE)


def _logs_client(cred):
    from azure.monitor.query import LogsQueryClient
    return LogsQueryClient(cred)


def _rows(response):
    """Normalize a LogsQueryClient response into list[dict]."""
    from azure.monitor.query import LogsQueryStatus
    out: list[dict[str, Any]] = []
    if getattr(response, "status", None) == LogsQueryStatus.PARTIAL:
        tables = response.partial_data or []
    else:
        tables = response.tables or []
    for t in tables:
        cols = [c for c in t.columns]
        for r in t.rows:
            out.append({cols[i]: r[i] for i in range(len(cols))})
    return out


def _query(cred, workspace_id: str, kql: str, tw: TimeWindow):
    client = _logs_client(cred)
    return _rows(client.query_workspace(workspace_id, kql, timespan=tw.timespan()))


# --------------------------------------------------------------------------- #
# Collection (read-only)
# --------------------------------------------------------------------------- #
def collect_heartbeat(report: Report, cred, workspace_id: str, computer: str, tw: TimeWindow) -> Optional[dict]:
    rows = _query(cred, workspace_id, _HEARTBEAT_KQL.format(computer=computer, time_filter=tw.kql_filter()), tw)
    report.sources.append("heartbeat")
    if not rows or rows[0].get("last_heartbeat") is None:
        return None
    last = rows[0]["last_heartbeat"]
    if isinstance(last, str):
        last = datetime.fromisoformat(last.replace("Z", "+00:00"))
    gap_min = (datetime.now(timezone.utc) - last).total_seconds() / 60.0
    return {"last": last.isoformat(), "gap_min": gap_min, "samples": int(rows[0].get("samples") or 0)}


def collect_perf(cred, workspace_id: str, computer: str, tw: TimeWindow,
                 obj: str, counter: str, instance_only: str = "") -> list[dict]:
    clause = f'| where InstanceName == "{instance_only}"' if instance_only else ""
    kql = _PERF_KQL.format(computer=computer, time_filter=tw.kql_filter(), obj=obj, counter=counter,
                          instance_clause=clause)
    return _query(cred, workspace_id, kql, tw)


def collect_event_errors(cred, workspace_id: str, computer: str, tw: TimeWindow) -> list[dict]:
    return _query(cred, workspace_id, _EVENT_ERR_KQL.format(computer=computer, time_filter=tw.kql_filter()), tw)


def collect_shutdown_events(cred, workspace_id: str, computer: str, tw: TimeWindow) -> Optional[dict]:
    rows = _query(cred, workspace_id,
                  _EVENT_SHUTDOWN_KQL.format(computer=computer, time_filter=tw.kql_filter()), tw)
    if not rows or not rows[0].get("cnt"):
        return None
    return {"count": int(rows[0]["cnt"]), "sample": str(rows[0].get("sample") or "")}



def collect_update(cred, workspace_id: str, computer: str, tw: TimeWindow) -> list[dict]:
    return _query(cred, workspace_id, _UPDATE_KQL.format(computer=computer, time_filter=tw.kql_filter()), tw)


def collect_vm_control_plane(report: Report, cred, resource_id: str) -> None:
    """Azure VM(Microsoft.Compute) 또는 Azure Arc-enabled server(Microsoft.HybridCompute)
    둘 다 지원한다 — 온프레미스/AWS/GCP 머신은 Arc로 온보딩되었을 때 후자 경로를 탄다."""
    m = RID_PARSE.match(resource_id or "")
    if m:
        sub_id, rg, name = m.groups()
        from azure.mgmt.compute import ComputeManagementClient
        client = ComputeManagementClient(cred, sub_id)
        vm = client.virtual_machines.get(rg, name, expand="instanceView")
        power_state = "unknown"
        for s in (vm.instance_view.statuses if vm.instance_view else []) or []:
            if (s.code or "").startswith("PowerState/"):
                power_state = s.display_status or s.code
                break
        os_type = None
        if vm.storage_profile and vm.storage_profile.os_disk:
            os_type = str(vm.storage_profile.os_disk.os_type)
        report.vm_info = {
            "resource_type": "azure_vm",
            "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
            "os_type": os_type,
            "power_state": power_state,
            "location": vm.location,
        }
        report.sources.append("compute:instanceView")
        return

    m = RID_PARSE_ARC.match(resource_id or "")
    if m:
        sub_id, rg, name = m.groups()
        from azure.mgmt.hybridcompute import HybridComputeManagementClient
        client = HybridComputeManagementClient(cred, sub_id)
        machine = client.machines.get(rg, name)
        report.vm_info = {
            "resource_type": "arc_machine",
            "status": machine.status,
            "os_type": machine.os_name,
            "os_version": machine.os_version,
            "agent_version": machine.agent_version,
            "location": machine.location,
        }
        report.sources.append("hybridcompute:machines")
        return

    report.add("control_plane", "info", "VM 제어 평면 미평가",
              "resource_id가 Microsoft.Compute/virtualMachines 또는 "
              "Microsoft.HybridCompute/machines(Azure Arc) 형식이 아니어서 건너뜁니다.")


# --------------------------------------------------------------------------- #
# Direct collection (WinRM) — works anywhere: on-prem, AWS, GCP, any cloud.
# No Azure Monitor / Log Analytics dependency; reads CIM/Get-WinEvent only.
# --------------------------------------------------------------------------- #
def resolve_password(env_name: str) -> str:
    pwd = os.environ.get(env_name)
    if pwd:
        return pwd
    if sys.stdin.isatty():
        return getpass.getpass(f"WinRM password ({env_name} 환경변수 미설정 — 직접 입력): ")
    raise SystemExit(f"{env_name} 환경변수가 설정되지 않았습니다(비대화형 환경). "
                     f"비밀번호는 CLI 인자로 받지 않으므로 환경변수로 전달하세요.")


def connect_winrm(args):
    import winrm
    port = args.winrm_port or (5986 if args.winrm_use_ssl else 5985)
    scheme = "https" if args.winrm_use_ssl else "http"
    endpoint = f"{scheme}://{args.host}:{port}/wsman"
    pwd = resolve_password(args.winrm_password_env)
    session = winrm.Session(endpoint, auth=(args.winrm_user, pwd), transport=args.winrm_transport,
                            server_cert_validation=("ignore" if args.winrm_cert_validation == "ignore"
                                                    else "validate"))
    probe = session.run_ps("$PSVersionTable.PSVersion.ToString()")
    if probe.status_code != 0:
        raise RuntimeError((probe.std_err or b"").decode("utf-8", errors="replace") or "WinRM 연결 실패")
    return session


def _winrm_run(session, ps_script: str) -> tuple[str, str, int]:
    r = session.run_ps(ps_script)
    return ((r.std_out or b"").decode("utf-8", errors="replace"),
           (r.std_err or b"").decode("utf-8", errors="replace"), r.status_code)


def parse_cpu_load(text: str) -> Optional[dict]:
    try:
        pct = float(text.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None
    return {"avg_val": pct, "max_val": pct}


def parse_os_memory(text: str) -> Optional[dict]:
    line = (text.strip().splitlines() or [""])[-1]
    parts = line.split("|")
    if len(parts) != 2:
        return None
    try:
        total_kb, free_kb = float(parts[0]), float(parts[1])
    except ValueError:
        return None
    if total_kb <= 0:
        return None
    used_pct = (1.0 - free_kb / total_kb) * 100.0
    return {"avg_val": used_pct, "max_val": used_pct}


def parse_logical_disks(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.strip().splitlines():
        parts = line.split("|")
        if len(parts) != 3:
            continue
        drive, size, free = parts
        try:
            size_f, free_f = float(size), float(free)
        except ValueError:
            continue
        if size_f <= 0:
            continue
        free_pct = free_f / size_f * 100.0
        rows.append({"InstanceName": drive, "avg_val": free_pct, "max_val": free_pct})
    return rows


def parse_event_counts(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.strip().splitlines():
        parts = line.split("|")
        if len(parts) != 3:
            continue
        log_name, level, cnt = parts
        try:
            n = int(cnt)
        except ValueError:
            continue
        rows.append({"EventLog": log_name, "EventLevelName": level, "count_": n})
    return rows


def parse_shutdown_events(text: str) -> Optional[dict]:
    line = (text.strip().splitlines() or [""])[-1]
    parts = line.split("|", 1)
    try:
        n = int(parts[0])
    except (ValueError, IndexError):
        return None
    if n <= 0:
        return None
    sample = parts[1] if len(parts) > 1 else ""
    return {"count": n, "sample": sample[:300]}


def parse_update_count(text: str) -> list[dict]:
    line = (text.strip().splitlines() or [""])[-1].strip()
    try:
        n = int(line)
    except ValueError:
        return []
    if n < 0:
        return []
    return [{"Classification": "Security Updates", "count_": n}]


def parse_services(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.strip().splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        name, display, state = parts
        rows.append({"Name": name, "DisplayName": display or name, "State": state})
    return rows


def parse_roles_features(text: str) -> list[dict]:
    return [{"Name": line.strip()} for line in text.strip().splitlines() if line.strip()]


def collect_cpu_direct(session) -> list[dict]:
    out, _err, code = _winrm_run(session,
        "(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average")
    row = parse_cpu_load(out) if code == 0 else None
    return [row] if row else []


def collect_memory_direct(session) -> list[dict]:
    out, _err, code = _winrm_run(session,
        "$os = Get-CimInstance Win32_OperatingSystem; "
        "'{0}|{1}' -f $os.TotalVisibleMemorySize,$os.FreePhysicalMemory")
    row = parse_os_memory(out) if code == 0 else None
    return [row] if row else []


def collect_disk_direct(session) -> list[dict]:
    out, _err, code = _winrm_run(session,
        "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | "
        "ForEach-Object { '{0}|{1}|{2}' -f $_.DeviceID,$_.Size,$_.FreeSpace }")
    return parse_logical_disks(out) if code == 0 else []


def collect_event_errors_direct(session, hours: int) -> list[dict]:
    out, _err, _code = _winrm_run(session,
        f"$since = (Get-Date).AddHours(-{hours}); "
        "Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2;StartTime=$since} "
        "-ErrorAction SilentlyContinue | Group-Object LogName,LevelDisplayName | "
        "ForEach-Object { '{0}|{1}|{2}' -f $_.Group[0].LogName,$_.Group[0].LevelDisplayName,$_.Count }")
    return parse_event_counts(out)


def collect_shutdown_direct(session, hours: int) -> Optional[dict]:
    out, _err, _code = _winrm_run(session,
        f"$since = (Get-Date).AddHours(-{hours}); "
        "$e = Get-WinEvent -FilterHashtable @{LogName='System';Id=41,6008;StartTime=$since} "
        "-ErrorAction SilentlyContinue; "
        "if ($e) { '{0}|{1}' -f @($e).Count, (@($e)[0].Message -replace \"`r`n\",' ') } else { '0|' }")
    return parse_shutdown_events(out)


def collect_update_direct(session) -> list[dict]:
    # Windows Update Agent COM(내장, 별도 모듈 불필요) — 네트워크/WSUS 상태에 따라 느릴 수 있어
    # 넉넉한 타임아웃과 실패 시 조용한 폴백(미평가)을 사용한다.
    out, _err, _code = _winrm_run(session,
        "try { "
        "$s = New-Object -ComObject Microsoft.Update.Session; "
        "$r = $s.CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Software'\"); "
        "@($r.Updates | Where-Object { $_.MsrcSeverity }).Count "
        "} catch { '-1' }")
    return parse_update_count(out)


def collect_services_direct(session) -> list[dict]:
    # 자동 시작(Automatic)으로 설정됐지만 현재 중지된 서비스만 조회한다(문제 후보만 추려서 경량화).
    out, _err, code = _winrm_run(session,
        "Get-CimInstance Win32_Service -Filter \"StartMode='Auto' and State!='Running'\" | "
        "ForEach-Object { '{0}|{1}|{2}' -f $_.Name,$_.DisplayName,$_.State }")
    return parse_services(out) if code == 0 else []


def collect_roles_features_direct(session) -> list[dict]:
    # Get-WindowsFeature은 Windows Server 전용(ServerManager 모듈) — 클라이언트 OS이거나
    # 모듈이 없으면 조용히 빈 목록으로 폴백한다(참고용 정보라 실패해도 진단은 계속된다).
    out, _err, code = _winrm_run(session,
        "try { Import-Module ServerManager -ErrorAction Stop; "
        "(Get-WindowsFeature | Where-Object { $_.Installed }).Name } catch { '' }")
    return parse_roles_features(out) if code == 0 else []


def collect_os_info_direct(session) -> dict[str, str]:
    out, _err, code = _winrm_run(session,
        "$os = Get-CimInstance Win32_OperatingSystem; "
        "'{0}|{1}|{2}' -f $os.Caption,$os.Version,$os.BuildNumber")
    if code != 0 or not out.strip():
        return {}
    parts = out.strip().splitlines()[-1].split("|")
    if len(parts) != 3:
        return {}
    return {"caption": parts[0], "version": parts[1], "build": parts[2]}


def collect_tpm_secureboot_direct(session) -> dict[str, str]:
    out, _err, _code = _winrm_run(session,
        "$tpmVer = 'unknown'; $sb = 'unknown'; "
        "try { $tpmVer = (Get-Tpm).ManufacturerVersion } catch {}; "
        "try { $sb = if (Confirm-SecureBootUEFI) {'Enabled'} else {'Disabled'} } catch { $sb = 'Unsupported' }; "
        "'{0}|{1}' -f $tpmVer,$sb")
    parts = (out.strip().splitlines() or ["unknown|unknown"])[-1].split("|")
    if len(parts) != 2:
        return {"tpm": "unknown", "secure_boot": "unknown"}
    return {"tpm": parts[0], "secure_boot": parts[1]}


def collect_installed_software_direct(session) -> list[str]:
    out, _err, code = _winrm_run(session,
        "$paths = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; "
        "Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | ForEach-Object { $_.DisplayName }")
    if code != 0:
        return []
    return [l.strip() for l in out.splitlines() if l.strip()]


# --------------------------------------------------------------------------- #
# Evaluation (report completeness: every category shows OK / 미평가)
# --------------------------------------------------------------------------- #
def evaluate_connectivity(report: Report, hb: Optional[dict], thr: dict) -> None:
    if hb is None:
        report.add("connectivity", "info", "에이전트 연결 상태 미평가",
                   "Heartbeat 데이터가 없습니다. Azure Monitor Agent가 설치·온보딩됐는지, "
                   "--computer 값이 Log Analytics의 Computer 컬럼과 일치하는지 확인하세요.",
                   recommendation="VM 확장(AzureMonitorWindowsAgent)과 데이터 수집 규칙(DCR) "
                                  "연결 상태를 점검하세요.")
        return
    gap = hb["gap_min"]
    if gap >= thr["heartbeat_crit_min"]:
        report.add("connectivity", "critical", "에이전트 하트비트 끊김",
                   f"마지막 하트비트가 {gap:.0f}분 전입니다(기준 critical ≥ "
                   f"{thr['heartbeat_crit_min']}분). 서버가 다운되었거나 에이전트가 응답하지 않습니다.",
                   {"gap_minutes": round(gap, 1), "last_heartbeat": hb["last"]},
                   recommendation="VM 전원/네트워크 상태와 Azure Monitor Agent 상태를 즉시 확인하세요.")
    elif gap >= thr["heartbeat_warn_min"]:
        report.add("connectivity", "warning", "에이전트 하트비트 지연",
                   f"마지막 하트비트가 {gap:.0f}분 전입니다(기준 warning ≥ "
                   f"{thr['heartbeat_warn_min']}분).",
                   {"gap_minutes": round(gap, 1), "last_heartbeat": hb["last"]},
                   recommendation="에이전트 상태와 네트워크 연결을 점검하세요.")
    else:
        report.add("connectivity", "ok", "에이전트 연결 양호",
                   f"마지막 하트비트 {gap:.1f}분 전 (샘플 {hb['samples']}건).")


def evaluate_cpu(report: Report, rows: list[dict], thr: dict) -> None:
    if not rows:
        report.add("cpu", "info", "CPU 사용률 미평가",
                   "Perf 데이터(Processor/% Processor Time)가 없습니다. 성능 카운터 데이터 "
                   "수집 규칙(DCR)에 Processor 카운터가 포함돼 있는지 확인하세요.")
        return
    avg_val = float(rows[0].get("avg_val") or 0.0)
    max_val = float(rows[0].get("max_val") or 0.0)
    if avg_val >= thr["cpu_crit"]:
        report.add("cpu", "critical", "CPU 사용률 매우 높음",
                   f"평균 {avg_val:.1f}% (최대 {max_val:.1f}%, 기준 critical ≥ {thr['cpu_crit']}%).",
                   {"avg": round(avg_val, 1), "max": round(max_val, 1)},
                   recommendation="상위 프로세스를 확인하고, 지속되면 워크로드 분산/스케일업을 검토하세요.")
    elif avg_val >= thr["cpu_warn"]:
        report.add("cpu", "warning", "CPU 사용률 높음",
                   f"평균 {avg_val:.1f}% (최대 {max_val:.1f}%, 기준 warning ≥ {thr['cpu_warn']}%).",
                   {"avg": round(avg_val, 1), "max": round(max_val, 1)},
                   recommendation="CPU 사용 추세를 모니터링하고 상위 프로세스를 점검하세요.")
    else:
        report.add("cpu", "ok", "CPU 사용률 양호", f"평균 {avg_val:.1f}% (최대 {max_val:.1f}%).")


def evaluate_memory(report: Report, rows: list[dict], thr: dict) -> None:
    if not rows:
        report.add("memory", "info", "메모리 사용률 미평가",
                   "Perf 데이터(Memory/% Committed Bytes In Use)가 없습니다. 데이터 수집 규칙(DCR)에 "
                   "Memory 카운터가 포함돼 있는지 확인하세요.")
        return
    avg_val = float(rows[0].get("avg_val") or 0.0)
    max_val = float(rows[0].get("max_val") or 0.0)
    if avg_val >= thr["mem_crit"]:
        report.add("memory", "critical", "메모리 사용률 매우 높음",
                   f"평균 커밋 메모리 사용률 {avg_val:.1f}% (최대 {max_val:.1f}%, "
                   f"기준 critical ≥ {thr['mem_crit']}%).",
                   {"avg": round(avg_val, 1), "max": round(max_val, 1)},
                   recommendation="메모리 누수 프로세스를 확인하고, 지속되면 메모리 증설을 검토하세요.")
    elif avg_val >= thr["mem_warn"]:
        report.add("memory", "warning", "메모리 사용률 높음",
                   f"평균 커밋 메모리 사용률 {avg_val:.1f}% (최대 {max_val:.1f}%, "
                   f"기준 warning ≥ {thr['mem_warn']}%).",
                   {"avg": round(avg_val, 1), "max": round(max_val, 1)},
                   recommendation="메모리 사용 추세를 모니터링하세요.")
    else:
        report.add("memory", "ok", "메모리 사용률 양호",
                   f"평균 커밋 메모리 사용률 {avg_val:.1f}% (최대 {max_val:.1f}%).")


def evaluate_disk(report: Report, rows: list[dict], thr: dict) -> None:
    if not rows:
        report.add("disk", "info", "디스크 여유공간 미평가",
                   "Perf 데이터(LogicalDisk/% Free Space)가 없습니다. 데이터 수집 규칙(DCR)에 "
                   "LogicalDisk 카운터가 포함돼 있는지 확인하세요.")
        return
    rows = [r for r in rows if r.get("InstanceName") not in (None, "_Total")]
    if not rows:
        report.add("disk", "info", "디스크 여유공간 미평가",
                   "볼륨별(드라이브) 데이터가 없어(전체 합계만 존재) 평가할 수 없습니다.")
        return
    worst = min(rows, key=lambda r: float(r.get("avg_val") or 0.0))
    free = float(worst.get("avg_val") or 0.0)
    drive = worst.get("InstanceName") or "?"
    if free <= thr["disk_free_crit"]:
        report.add("disk", "critical", f"디스크 여유공간 부족: {drive}",
                   f"여유공간 {free:.1f}% (기준 critical ≤ {thr['disk_free_crit']}%).",
                   {"drive": drive, "free_pct": round(free, 1)},
                   recommendation=f"{drive} 드라이브의 불필요한 파일/로그를 정리하거나 볼륨을 확장하세요.")
    elif free <= thr["disk_free_warn"]:
        report.add("disk", "warning", f"디스크 여유공간 주의: {drive}",
                   f"여유공간 {free:.1f}% (기준 warning ≤ {thr['disk_free_warn']}%).",
                   {"drive": drive, "free_pct": round(free, 1)},
                   recommendation=f"{drive} 드라이브 사용량 증가 추세를 모니터링하세요.")
    else:
        report.add("disk", "ok", "디스크 여유공간 양호",
                   f"가장 여유공간이 적은 드라이브도 {free:.1f}% 여유 ({drive}).")


def evaluate_logs(report: Report, rows: list[dict], thr: dict) -> None:
    if not rows:
        report.add("eventlog", "info", "이벤트 로그 미평가",
                   "Event 테이블에 Error/Critical 레코드가 없습니다(수집 미설정이거나 실제로 "
                   "오류가 없을 수 있습니다). 데이터 수집 규칙(DCR)에 System/Application "
                   "이벤트 로그가 포함돼 있는지 확인하세요.")
        return
    total = sum(int(r.get("count_") or r.get("count") or 0) for r in rows)
    top = sorted(rows, key=lambda r: int(r.get("count_") or r.get("count") or 0), reverse=True)[:5]
    detail = ", ".join(f"{r.get('EventLog')}/{r.get('EventLevelName')}={int(r.get('count_') or r.get('count') or 0)}"
                       for r in top)
    if total >= thr["log_err_crit"]:
        report.add("eventlog", "critical", "이벤트 로그 오류 다수 발생",
                   f"Error/Critical 총 {total}건 (기준 critical ≥ {thr['log_err_crit']}건). {detail}",
                   {"total": total, "by_log": top},
                   recommendation="이벤트 뷰어에서 반복되는 오류 원인을 확인하세요(드라이버/서비스/앱 크래시 등).")
    elif total >= thr["log_err_warn"]:
        report.add("eventlog", "warning", "이벤트 로그 오류 발생",
                   f"Error/Critical 총 {total}건 (기준 warning ≥ {thr['log_err_warn']}건). {detail}",
                   {"total": total, "by_log": top},
                   recommendation="오류 패턴이 늘어나는지 모니터링하세요.")
    else:
        report.add("eventlog", "ok", "이벤트 로그 양호", f"Error/Critical 총 {total}건.")


def evaluate_shutdown(report: Report, sd: Optional[dict]) -> None:
    if sd is None:
        report.add("stability", "ok", "예기치 않은 재시작 없음",
                   "Kernel-Power(41) / EventLog(6008) 이벤트가 발견되지 않았습니다.")
        return
    report.add("stability", "critical", "예기치 않은 종료/재시작 감지",
               f"{sd['count']}건 발생. 예: {sd['sample'][:200]}",
               {"count": sd["count"]},
               recommendation="전원/드라이버/하드웨어 이상 여부를 확인하세요(비정상 종료가 "
                              "반복되면 하드웨어 점검이 필요할 수 있습니다).")


def evaluate_update(report: Report, rows: list[dict]) -> None:
    if not rows:
        report.add("patch", "info", "패치 준수 상태 미평가",
                   "Update 테이블 데이터가 없습니다. Update Management(또는 Azure Update "
                   "Manager) 솔루션이 활성화돼 있지 않을 수 있습니다.",
                   recommendation="Azure Update Manager를 이 서버에 활성화하면 패치 준수 "
                                  "상태를 진단할 수 있습니다.")
        return
    security = sum(int(r.get("count_") or r.get("count") or 0) for r in rows
                  if "Security" in str(r.get("Classification") or ""))
    if security >= 10:
        report.add("patch", "critical", "보안 업데이트 다수 누락",
                   f"적용 대기 중인 보안 업데이트 {security}건.", {"security_missing": security},
                   recommendation="보안 업데이트를 우선 적용하세요(Azure Update Manager 사용 권장).")
    elif security >= 1:
        report.add("patch", "warning", "보안 업데이트 누락",
                   f"적용 대기 중인 보안 업데이트 {security}건.", {"security_missing": security},
                   recommendation="다음 유지보수 기간에 보안 업데이트를 적용하세요.")
    else:
        report.add("patch", "ok", "패치 상태 양호", "대기 중인 보안 업데이트가 없습니다.")


def evaluate_services(report: Report, rows: list[dict], thr: dict) -> None:
    if report.collection_mode != "direct":
        report.add("services", "info", "서비스 상태 미평가",
                   "자동 시작(Automatic) 서비스의 중지 여부는 direct 모드(WinRM)에서만 진단합니다 "
                   "(서비스 인벤토리는 기본 Azure Monitor 텔레메트리에 포함되지 않습니다).")
        return
    if not rows:
        report.add("services", "ok", "서비스 상태 양호",
                   "자동 시작으로 설정된 서비스 중 중지된 서비스가 없습니다.")
        return
    count = len(rows)
    names = ", ".join(r.get("DisplayName") or r.get("Name") or "?" for r in rows[:10])
    more = " 등" if count > 10 else ""
    if count >= thr["services_crit"]:
        report.add("services", "critical", "자동 시작 서비스 다수 중지",
                   f"자동 시작으로 설정됐지만 중지된 서비스 {count}건: {names}{more} "
                   f"(기준 critical ≥ {thr['services_crit']}건).",
                   {"count": count, "services": [r["Name"] for r in rows]},
                   recommendation="중지된 서비스가 의도된 것인지 확인하고, 아니라면 즉시 시작하거나 원인을 조사하세요.")
    elif count >= thr["services_warn"]:
        report.add("services", "warning", "자동 시작 서비스 중지됨",
                   f"자동 시작으로 설정됐지만 중지된 서비스 {count}건: {names}{more} "
                   f"(기준 warning ≥ {thr['services_warn']}건).",
                   {"count": count, "services": [r["Name"] for r in rows]},
                   recommendation="해당 서비스가 의도적으로 중지된 것인지 확인하세요.")


def evaluate_roles_features(report: Report, rows: list[dict]) -> None:
    if report.collection_mode != "direct":
        report.add("roles_features", "info", "설치된 역할/기능 미평가",
                   "Windows Server 역할/기능 목록은 direct 모드(WinRM)에서만 조회합니다.")
        return
    if not rows:
        report.add("roles_features", "info", "설치된 역할/기능 확인 불가",
                   "Get-WindowsFeature 결과가 없습니다(클라이언트 OS이거나 ServerManager 모듈이 "
                   "없는 환경일 수 있습니다 — 참고용 정보이며 문제로 간주하지 않습니다).")
        return
    names = ", ".join(r["Name"] for r in rows[:15])
    more = " 등" if len(rows) > 15 else ""
    report.add("roles_features", "info", f"설치된 역할/기능 {len(rows)}개",
              f"{names}{more}",
              {"count": len(rows), "features": [r["Name"] for r in rows]})


def evaluate_os_lifecycle(report: Report, os_info: dict[str, str], thr: dict) -> None:
    if report.collection_mode != "direct":
        report.add("os_lifecycle", "info", "OS 수명주기 미평가",
                   "OS EOL 수명주기는 direct 모드(WinRM)에서만 진단합니다 — --skip-upgrade-check로 "
                   "꺼져 있거나 azure-monitor 모드이면 표시됩니다.")
        return
    caption = os_info.get("caption") or ""
    if not caption:
        report.add("os_lifecycle", "info", "OS 정보 확인 불가",
                  "Win32_OperatingSystem 조회에 실패해 OS 버전을 확인하지 못했습니다.")
        return

    entry = next((e for e in OS_LIFECYCLE if e["match"].lower() in caption.lower()), None)
    if not entry:
        report.add("os_lifecycle", "info", f"수명주기 정보 없음: {caption}",
                  "임베디드 수명주기 표에 없는 OS입니다. 공식 Microsoft Lifecycle 페이지에서 "
                  "직접 확인하세요.", {"caption": caption})
        return

    today = date.today()
    eol = entry["eol"]
    days_left = (eol - today).days
    name = entry["name"]
    esm_eol = entry.get("esm_eol")

    if days_left < 0:
        detail = f"{name}은(는) {eol.isoformat()}에 지원이 종료되었습니다({-days_left}일 경과)."
        if esm_eol and today <= esm_eol:
            detail += f" 확장 보안 업데이트(ESU)가 {esm_eol.isoformat()}까지 가능할 수 있습니다."
        report.add("os_lifecycle", "critical", f"OS 지원 종료: {name}", detail,
                  {"eol": eol.isoformat(), "days_since_eol": -days_left, "caption": caption},
                  recommendation="최신 지원 버전으로 업그레이드하거나(사내 정책에 따라 신규 서버로 "
                                 "교체), 불가피하면 ESU(확장 보안 업데이트)를 신청하세요.")
    elif days_left <= thr["eol_warn_days"]:
        report.add("os_lifecycle", "warning", f"OS 지원 종료 임박: {name}",
                  f"{eol.isoformat()}에 지원이 종료됩니다({days_left}일 남음).",
                  {"eol": eol.isoformat(), "days_left": days_left, "caption": caption},
                  recommendation="업그레이드 일정을 계획하세요.")
    else:
        report.add("os_lifecycle", "ok", f"OS 지원 기간 양호: {name}",
                  f"지원 종료까지 {days_left}일 남음({eol.isoformat()}).")

    report.add("os_version", "info", "OS 버전", f"{caption} (빌드 {os_info.get('build', '?')}, 참고용).")


def evaluate_win11_readiness(report: Report, os_info: dict[str, str], tpm_sb: dict[str, str]) -> None:
    if report.collection_mode != "direct":
        return
    caption = (os_info.get("caption") or "").lower()
    if "windows 10" not in caption:
        return  # Windows 10이 아니면 이 점검은 해당 없음
    tpm = tpm_sb.get("tpm", "unknown")
    sb = tpm_sb.get("secure_boot", "unknown")
    tpm_ok = tpm not in ("unknown", "") and not tpm.startswith("1.2")
    if sb == "Enabled" and tpm_ok:
        report.add("win11_readiness", "ok", "Windows 11 하드웨어 요건 충족(참고)",
                  f"TPM {tpm}, Secure Boot {sb}. (CPU 세대 등 다른 요건은 별도 확인 필요)")
    else:
        report.add("win11_readiness", "warning", "Windows 11 하드웨어 요건 미충족 가능성",
                  f"TPM {tpm}, Secure Boot {sb}. TPM 2.0과 Secure Boot 활성화가 필요합니다.",
                  {"tpm": tpm, "secure_boot": sb},
                  recommendation="TPM 2.0 활성화(BIOS/UEFI) 및 Secure Boot 활성화 여부를 확인하세요. "
                                 "CPU 세대 등 다른 요건은 PC Health Check 도구로 추가 확인하세요.")


def evaluate_known_eol_software(report: Report, software: list[str]) -> None:
    if report.collection_mode != "direct":
        report.add("software_eol", "info", "설치 프로그램 EOL 미평가",
                   "설치 프로그램 목록은 direct 모드(WinRM)에서만 조회합니다.")
        return
    if not software:
        report.add("software_eol", "info", "설치 프로그램 목록 미평가",
                  "레지스트리 Uninstall 키 조회에 실패해 설치 프로그램을 확인하지 못했습니다.")
        return
    hits = []
    for rule in KNOWN_EOL_SOFTWARE:
        pat = re.compile(rule["pattern"], re.IGNORECASE)
        matched = [s for s in software if pat.search(s)]
        if matched:
            hits.append((rule, matched))
    if not hits:
        report.add("software_eol", "ok", "알려진 EOL 소프트웨어 없음",
                  f"설치된 프로그램 {len(software)}개 중 알려진 EOL/구식 소프트웨어 패턴과 일치하는 "
                  f"항목이 없습니다.")
        return
    for rule, matched in hits:
        report.add("software_eol", "warning", f"EOL 소프트웨어 발견: {rule['name']}",
                  f"설치된 항목: {', '.join(matched[:5])}"
                  + ("…" if len(matched) > 5 else "") + f" (EOL: {rule['eol']}). {rule['note']}",
                  {"software": matched, "eol": rule["eol"]},
                  recommendation=rule["note"])


def evaluate_recommended_software(report: Report, software: list[str]) -> None:
    if report.collection_mode != "direct":
        report.add("recommended_software", "info", "권장 소프트웨어 점검 미평가",
                   "권장 소프트웨어 설치 여부는 direct 모드(WinRM)에서만 확인합니다.")
        return
    if not software:
        report.add("recommended_software", "info", "권장 소프트웨어 점검 미평가",
                  "설치 프로그램 목록을 가져오지 못해 권장 소프트웨어 설치 여부를 확인할 수 없습니다.")
        return
    missing = []
    for item in RECOMMENDED_SOFTWARE:
        pat = re.compile(item["pattern"], re.IGNORECASE)
        if not any(pat.search(s) for s in software):
            missing.append(item)
    if not missing:
        report.add("recommended_software", "ok", "권장 소프트웨어 모두 설치됨",
                  "기본 관리 도구 세트(엔드포인트 보호/관리 에이전트/최신 PowerShell/백업 에이전트)가 "
                  "모두 확인되었습니다.")
        return
    for item in missing:
        report.add("recommended_software", "info", f"권장 소프트웨어 미설치: {item['check']}",
                  item["reason"], recommendation=f"{item['check']} 설치를 검토하세요.")


def evaluate_control_plane(report: Report) -> None:
    if not report.vm_info:
        return
    if report.vm_info.get("resource_type") == "arc_machine":
        status = str(report.vm_info.get("status") or "").lower()
        if status in ("disconnected", "error"):
            report.add("control_plane", "critical", "Arc 에이전트 연결 끊김",
                      f"현재 상태: {report.vm_info.get('status')}.",
                      {"status": report.vm_info.get("status")},
                      recommendation="대상 서버의 Azure Connected Machine 에이전트(himds) 상태와 "
                                     "네트워크 연결을 확인하세요.")
        elif status == "expired":
            report.add("control_plane", "warning", "Arc 에이전트 인증서 만료",
                      f"현재 상태: {report.vm_info.get('status')}.",
                      {"status": report.vm_info.get("status")},
                      recommendation="azcmagent 재연결이 필요할 수 있습니다.")
        elif status == "connected":
            report.add("control_plane", "ok", "Arc 에이전트 연결 정상",
                      f"{report.vm_info.get('status')}, 에이전트 버전 {report.vm_info.get('agent_version')}.")
        else:
            report.add("control_plane", "info", "Arc 에이전트 상태 확인 불가",
                      f"상태 문자열: {report.vm_info.get('status')}.")
        os_type = str(report.vm_info.get("os_type") or "")
        if os_type and "windows" not in os_type.lower():
            report.add("control_plane", "warning", "OS 종류 불일치",
                      f"ARM에 기록된 OS 종류가 '{os_type}'입니다. windows_diagnose 대상이 맞는지 확인하세요.")
        return

    power = str(report.vm_info.get("power_state") or "").lower()
    if "deallocat" in power or "stopped" in power:
        report.add("control_plane", "critical", "VM 전원 꺼짐",
                   f"현재 전원 상태: {report.vm_info.get('power_state')}.",
                   {"power_state": report.vm_info.get("power_state")},
                   recommendation="VM을 시작하거나, 의도된 중지 상태인지 확인하세요.")
    elif "running" in power:
        report.add("control_plane", "ok", "VM 전원 상태 정상",
                   f"{report.vm_info.get('power_state')}, 크기 {report.vm_info.get('vm_size')}.")
    else:
        report.add("control_plane", "info", "VM 전원 상태 확인 불가",
                   f"상태 문자열: {report.vm_info.get('power_state')}.")
    os_type = str(report.vm_info.get("os_type") or "")
    if os_type and os_type.lower() != "windows":
        report.add("control_plane", "warning", "OS 종류 불일치",
                   f"ARM에 기록된 OS 종류가 '{os_type}'입니다. windows_diagnose 대상이 맞는지 확인하세요.")


def evaluate(report: Report, data: dict, thr: dict) -> None:
    if report.collection_mode != "direct":
        # direct 모드는 WinRM 연결 성공 자체가 연결성 확인이므로 build_report_direct()에서
        # 이미 "ok" finding을 추가했다 — 여기서 중복으로 미평가를 추가하지 않는다.
        evaluate_connectivity(report, data.get("heartbeat"), thr)
    evaluate_cpu(report, data.get("cpu") or [], thr)
    evaluate_memory(report, data.get("memory") or [], thr)
    evaluate_disk(report, data.get("disk") or [], thr)
    evaluate_logs(report, data.get("log_errors") or [], thr)
    evaluate_shutdown(report, data.get("shutdown"))
    evaluate_update(report, data.get("update") or [])
    evaluate_services(report, data.get("services") or [], thr)
    evaluate_roles_features(report, data.get("roles_features") or [])
    evaluate_os_lifecycle(report, data.get("os_info") or {}, thr)
    evaluate_win11_readiness(report, data.get("os_info") or {}, data.get("tpm_sb") or {})
    evaluate_known_eol_software(report, data.get("software") or [])
    evaluate_recommended_software(report, data.get("software") or [])
    evaluate_control_plane(report)


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
_SECRET = re.compile(r'(?i)(password|pwd|secret|connection ?string|accountkey|sas|token|apikey)\s*[=:]\s*\S+')
_RRN = re.compile(r'\b\d{6}-\d{7}\b')
_EMAIL = re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b')
_INJECT = re.compile(r'(?i)(ignore (all|previous)|system prompt|<\s*important\s*>|assistant\s*:|tool_call)')


def _clean(v):
    if isinstance(v, str):
        v = _SECRET.sub(r'\1=***', v)
        v = _RRN.sub('[PII]', v)
        v = _EMAIL.sub('[PII]', v)
        v = _INJECT.sub('[filtered]', v)
        return v
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_clean(x) for x in v]
    return v


def _report_payload(report: Report) -> dict:
    payload = _clean(asdict(report))
    payload["worst_severity"] = report.worst_severity()
    payload["health_score"] = report.health_score()
    payload["severity_counts"] = report.severity_counts()
    payload["summary"] = _clean(report.summary_text())
    payload["recommended_actions"] = _clean(report.recommended_actions())
    return payload


def render_json(report: Report) -> str:
    return json.dumps(_report_payload(report), ensure_ascii=False, indent=2)


_SEV_TAG = {"critical": "[위험]", "warning": "[주의]", "info": "[정보]", "ok": "[양호]"}


def render_table(report: Report) -> str:
    counts = report.severity_counts()
    lines = [
        f"{TOOL_NAME} v{TOOL_VERSION}",
        f"대상     : {report.computer or '(미지정)'}",
        f"수집방식 : {report.collection_mode}",
        f"기간     : {report.window}   생성: {report.generated_at}",
        f"소스     : {', '.join(report.sources) or '(없음)'}",
        f"건강 점수: {report.health_score()}/100   최악: "
        f"{SEV_LABEL_KO.get(report.worst_severity(), report.worst_severity())}",
        f"발견     : 위험 {counts['critical']}, 주의 {counts['warning']}, "
        f"정보 {counts['info']}, 양호 {counts['ok']}",
        "-" * 78,
        "[진단]",
    ]
    for c in sorted(report.checks, key=lambda x: SEVERITY_ORDER[x.severity]):
        lines.append(f"{_SEV_TAG[c.severity]} {c.category:<14} {c.title}")
        lines.append(f"        {c.detail}")
        if c.recommendation:
            lines.append(f"        \u2192 조치: {c.recommendation}")
    actions = report.recommended_actions()
    if actions:
        lines.append("-" * 78)
        lines.append("권장 조치 (우선순위 순):")
        for i, a in enumerate(actions, 1):
            lines.append(f"  {i}. [{SEV_LABEL_KO.get(a['severity'], a['severity'])}] {a['title']}")
            lines.append(f"     {a['action']}")
    return "\n".join(lines)


_SEV_COLOR = {"critical": "#d93a3a", "warning": "#e8b42e", "info": "#3a7bd9", "ok": "#2ea84a"}


def render_html(report: Report) -> str:
    from html import escape as _esc
    score = report.health_score()
    score_color = "#2ea84a" if score >= 80 else "#e8b42e" if score >= 50 else "#d93a3a"
    counts = report.severity_counts()

    rows = []
    for c in sorted(report.checks, key=lambda x: SEVERITY_ORDER[x.severity]):
        color = _SEV_COLOR.get(c.severity, "#666")
        rec = (f'<div class="fix">\u2192 {_esc(c.recommendation)}</div>'
               if c.recommendation else "")
        rows.append(
            "<tr>"
            f'<td><span class="sev" style="background:{color}">{_esc(SEV_LABEL_KO.get(c.severity, c.severity))}</span></td>'
            f"<td>{_esc(c.category)}</td><td>{_esc(c.title)}</td>"
            f"<td>{_esc(c.detail)}{rec}</td></tr>"
        )
    rows_html = "\n".join(rows) or '<tr><td colspan="4">진단 항목이 없습니다.</td></tr>'

    vm_info_html = ""
    if report.vm_info:
        vm_info_html = ("<div class=\"summary\">VM 정보: "
                        f"{_esc(str(report.vm_info.get('vm_size') or '-'))}, "
                        f"{_esc(str(report.vm_info.get('os_type') or '-'))}, "
                        f"{_esc(str(report.vm_info.get('power_state') or '-'))}</div>")

    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<title>{_esc(TOOL_NAME)} — {_esc(report.computer)}</title>
<style>
  body {{ font-family:'Segoe UI',Arial,sans-serif; margin:24px; color:#222; }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  .meta {{ color:#666; font-size:13px; margin-bottom:12px; line-height:1.6; }}
  .score {{ display:inline-block; padding:6px 14px; border-radius:10px; color:#fff;
            font-weight:700; background:{score_color}; }}
  .summary {{ margin:12px 0; padding:10px 12px; background:#f7f9fc; border:1px solid #dbe4f0;
              border-radius:4px; font-size:13px; }}
  table {{ border-collapse:collapse; width:100%; font-size:13px; margin-top:12px; }}
  th,td {{ border:1px solid #ddd; padding:8px 10px; text-align:left; vertical-align:top; }}
  th {{ background:#f2f2f2; }}
  tr:nth-child(even) td {{ background:#fafafa; }}
  .sev {{ display:inline-block; padding:2px 8px; border-radius:10px; color:#fff;
          font-size:12px; font-weight:600; }}
  .fix {{ margin-top:6px; padding:6px 8px; background:#eef4ff; border-left:3px solid #3a7bd9;
          color:#1a3b6b; font-size:12px; border-radius:2px; }}
</style></head><body>
<h1>{_esc(TOOL_NAME)} v{_esc(TOOL_VERSION)} — Windows OS 진단</h1>
<div class="meta">
  대상: <b>{_esc(report.computer or '(미지정)')}</b> &nbsp; 수집방식: {_esc(report.collection_mode)}<br>
  기간: {_esc(report.window)} &nbsp; 생성: {_esc(report.generated_at)} &nbsp;
  소스: {_esc(', '.join(report.sources) or '(없음)')}<br>
  <div style="margin-top:8px">건강 점수: <span class="score">{score}/100</span> &nbsp;
    <span style="color:#d93a3a">\u25cf {counts['critical']}</span>
    <span style="color:#e8b42e">\u25cf {counts['warning']}</span>
    <span style="color:#3a7bd9">\u25cf {counts['info']}</span>
    <span style="color:#2ea84a">\u25cf {counts['ok']}</span>
  </div>
</div>
<div class="summary">{_esc(report.summary_text())}</div>
{vm_info_html}
<table>
  <thead><tr><th>심각도</th><th>범주</th><th>제목</th><th>상세 &amp; 권장 조치</th></tr></thead>
  <tbody>
{rows_html}
  </tbody>
</table>
</body></html>"""


# --------------------------------------------------------------------------- #
# Demo data (offline validation, no Azure needed)
# --------------------------------------------------------------------------- #
def build_demo_report(hours: int) -> Report:
    r = Report(computer="WIN-DEMO01",
               generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
               window=f"last {hours}h", sources=["demo"])
    data = {
        "heartbeat": {"last": datetime.now(timezone.utc).isoformat(), "gap_min": 2.0, "samples": 480},
        "cpu": [{"InstanceName": "_Total", "avg_val": 91.4, "max_val": 99.0}],
        "memory": [{"InstanceName": "", "avg_val": 88.2, "max_val": 96.0}],
        "disk": [{"InstanceName": "C:", "avg_val": 7.5, "max_val": 8.1},
                 {"InstanceName": "D:", "avg_val": 42.0, "max_val": 44.0}],
        "log_errors": [{"EventLog": "System", "EventLevelName": "Error", "count_": 62},
                       {"EventLog": "Application", "EventLevelName": "Critical", "count_": 3}],
        "shutdown": {"count": 1, "sample": "The system rebooted without cleanly shutting down first."},
        "update": [{"Classification": "Security Updates", "count_": 4}],
    }
    r.vm_info = {"vm_size": "Standard_D4s_v5", "os_type": "Windows", "power_state": "VM running",
                "location": "koreacentral"}
    return r, data


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _parse_iso_dt(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"invalid ISO 8601 datetime: {value!r}") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Read-only Windows OS diagnostic tool. Recommended path: onboard the server "
                    "to Azure Arc, then use Log Analytics telemetry (default, --workspace-id + "
                    "--resource-id pointing at the Microsoft.HybridCompute/machines resource).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    src = p.add_argument_group("collection mode")
    src.add_argument("--source", choices=["azure-monitor", "direct"], default="azure-monitor",
                     help=argparse.SUPPRESS)

    am = p.add_argument_group("azure-monitor mode (권장: Azure Arc 연결 후 사용)")
    am.add_argument("--computer", help="Log Analytics 'Computer' column value (required unless --demo)")
    am.add_argument("--workspace-id", help="Log Analytics workspace GUID")
    am.add_argument("--start-time", type=_parse_iso_dt, default=None,
                    help="조회 시작 시각(ISO 8601, 예: 2026-07-29T00:00:00Z). 지정 시 --hours 대신 "
                         "이 절대 기간을 사용합니다(azure-monitor 모드 전용).")
    am.add_argument("--end-time", type=_parse_iso_dt, default=None,
                    help="조회 종료 시각(ISO 8601). 미지정 시 현재 시각. --start-time과 함께 사용.")

    # direct 모드(WinRM)는 Azure Arc를 연결할 수 없는 예외적인 경우를 위한 숨은 옵션이다 —
    # --help에는 노출하지 않지만(help=SUPPRESS), --source direct 로 명시하면 그대로 동작한다.
    # 자세한 사용법은 README의 "숨은 옵션(Azure Arc 없이 사용)" 절을 참고할 것.
    dm = p.add_argument_group(argparse.SUPPRESS)
    dm.add_argument("--host", help=argparse.SUPPRESS)
    dm.add_argument("--winrm-port", type=int, default=0, help=argparse.SUPPRESS)
    dm.add_argument("--winrm-user", help=argparse.SUPPRESS)
    dm.add_argument("--winrm-password-env", default="WINDOWS_DIAGNOSE_WINRM_PASSWORD",
                    help=argparse.SUPPRESS)
    dm.add_argument("--winrm-transport", choices=["ntlm", "kerberos", "credssp", "basic"], default="ntlm",
                    help=argparse.SUPPRESS)
    dm.add_argument("--winrm-use-ssl", action="store_true", help=argparse.SUPPRESS)
    dm.add_argument("--winrm-cert-validation", choices=["validate", "ignore"], default="validate",
                    help=argparse.SUPPRESS)

    ctl = p.add_argument_group("control-plane (Azure Arc 연결 시 권장, Azure VM도 지원)")
    ctl.add_argument("--resource-id", default="",
                     help="VM/Arc 머신 ARM resource id (Microsoft.Compute/virtualMachines 또는 "
                          "Microsoft.HybridCompute/machines) — 연결 상태/전원 상태/OS 버전 조회")

    safety = p.add_argument_group("safety")
    safety.add_argument("--skip-patch-check", action="store_true", help=argparse.SUPPRESS)
    safety.add_argument("--skip-upgrade-check", action="store_true",
                        help="OS EOL 수명주기/설치 프로그램 전체 목록 조회를 생략합니다(대상 서버 부하 감소).")

    tn = p.add_argument_group("tunables")
    tn.add_argument("--hours", type=int, default=24)
    tn.add_argument("--cpu-warn", type=float, default=DEFAULTS["cpu_warn"])
    tn.add_argument("--cpu-crit", type=float, default=DEFAULTS["cpu_crit"])
    tn.add_argument("--mem-warn", type=float, default=DEFAULTS["mem_warn"])
    tn.add_argument("--mem-crit", type=float, default=DEFAULTS["mem_crit"])
    tn.add_argument("--disk-free-warn", type=float, default=DEFAULTS["disk_free_warn"])
    tn.add_argument("--disk-free-crit", type=float, default=DEFAULTS["disk_free_crit"])
    tn.add_argument("--heartbeat-warn-min", type=int, default=DEFAULTS["heartbeat_warn_min"])
    tn.add_argument("--heartbeat-crit-min", type=int, default=DEFAULTS["heartbeat_crit_min"])
    tn.add_argument("--log-err-warn", type=int, default=DEFAULTS["log_err_warn"])
    tn.add_argument("--log-err-crit", type=int, default=DEFAULTS["log_err_crit"])
    tn.add_argument("--services-warn", type=int, default=DEFAULTS["services_warn"])
    tn.add_argument("--services-crit", type=int, default=DEFAULTS["services_crit"])
    tn.add_argument("--eol-warn-days", type=int, default=DEFAULTS["eol_warn_days"],
                    help="OS EOL까지 이 일수 이내면 warning로 표시")

    out = p.add_argument_group("output")
    out.add_argument("--format", choices=["table", "json", "html"], default="table")
    out.add_argument("--output", "-o", help="Write report to this path instead of stdout")
    out.add_argument("--save-snapshot", default="",
                     help="이번 실행 결과(JSON)를 이 경로에 JSON Lines로 추가 저장합니다 — "
                          "주기 실행(cron/작업 스케쥴러)과 결합하면 직접 시계열 이력을 축적할 수 있습니다.")
    out.add_argument("--demo", action="store_true",
                     help="Use synthetic data (no connection) to preview the report")
    out.add_argument("--exit-code", action="store_true",
                     help="Exit 2 if any critical, 1 if any warning, else 0")
    return p


def _thresholds(args) -> dict:
    return {"cpu_warn": args.cpu_warn, "cpu_crit": args.cpu_crit,
           "mem_warn": args.mem_warn, "mem_crit": args.mem_crit,
           "disk_free_warn": args.disk_free_warn, "disk_free_crit": args.disk_free_crit,
           "heartbeat_warn_min": args.heartbeat_warn_min, "heartbeat_crit_min": args.heartbeat_crit_min,
           "log_err_warn": args.log_err_warn, "log_err_crit": args.log_err_crit,
           "services_warn": args.services_warn, "services_crit": args.services_crit,
           "eol_warn_days": args.eol_warn_days}


def _maybe_control_plane(report: Report, args, nag_if_missing: bool) -> None:
    """resource_id가 있으면 어느 모드에서든 VM 제어 평면을 조회한다(Azure/Arc VM인 경우)."""
    if not args.resource_id:
        if nag_if_missing:
            report.request_input(
                "resource_id",
                "VM 전원 상태/크기/OS 버전(제어 평면)을 확인하려면 ARM resource_id가 필요합니다.",
                "Resource Graph: resources | where type =~ 'microsoft.compute/virtualmachines' "
                "and name =~ '<computer>' | project name, id, resourceGroup, subscriptionId",
                "windows-diagnose --computer <컴퓨터명> --workspace-id <GUID> "
                "--resource-id /subscriptions/<sub>/resourceGroups/<rg>/providers/"
                "Microsoft.Compute/virtualMachines/<vm> --format json")
        return
    try:
        from azure.identity import DefaultAzureCredential
        cred = DefaultAzureCredential()
        collect_vm_control_plane(report, cred, args.resource_id)
    except Exception as e:  # noqa: BLE001
        report.add("control_plane", "info", "VM 제어 평면 조회 실패", str(e))


def build_report_azure_monitor(args, thr: dict) -> Report:
    if not args.computer:
        raise SystemExit("--computer 는 필수입니다(또는 --demo)")

    tw = TimeWindow(hours=args.hours, start=args.start_time, end=args.end_time)
    report = Report(computer=args.computer, collection_mode="azure-monitor",
                    generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    window=tw.label())
    cred = None
    try:
        from azure.identity import DefaultAzureCredential
        cred = DefaultAzureCredential()
    except Exception as e:  # noqa: BLE001
        report.add("auth", "info", "Entra 자격 증명 사용 불가", str(e))

    data: dict[str, Any] = {}
    if cred is not None and args.workspace_id:
        try:
            data["heartbeat"] = collect_heartbeat(report, cred, args.workspace_id, args.computer, tw)
        except Exception as e:  # noqa: BLE001
            report.add("connectivity", "info", "Heartbeat 조회 실패", str(e))
        try:
            data["cpu"] = collect_perf(cred, args.workspace_id, args.computer, tw,
                                       "Processor", "% Processor Time", "_Total")
        except Exception as e:  # noqa: BLE001
            report.add("cpu", "info", "CPU Perf 조회 실패", str(e))
        try:
            data["memory"] = collect_perf(cred, args.workspace_id, args.computer, tw,
                                          "Memory", "% Committed Bytes In Use")
        except Exception as e:  # noqa: BLE001
            report.add("memory", "info", "메모리 Perf 조회 실패", str(e))
        try:
            data["disk"] = collect_perf(cred, args.workspace_id, args.computer, tw,
                                        "LogicalDisk", "% Free Space")
        except Exception as e:  # noqa: BLE001
            report.add("disk", "info", "디스크 Perf 조회 실패", str(e))
        try:
            data["log_errors"] = collect_event_errors(cred, args.workspace_id, args.computer, tw)
        except Exception as e:  # noqa: BLE001
            report.add("eventlog", "info", "Event 조회 실패", str(e))
        try:
            data["shutdown"] = collect_shutdown_events(cred, args.workspace_id, args.computer, tw)
        except Exception as e:  # noqa: BLE001
            report.add("stability", "info", "종료 이벤트 조회 실패", str(e))
        try:
            data["update"] = collect_update(cred, args.workspace_id, args.computer, tw)
        except Exception as e:  # noqa: BLE001
            report.add("patch", "info", "Update 조회 실패", str(e))
    elif cred is not None:
        report.add("target", "info", "데이터 소스 미지정",
                   "--workspace-id 가 없어 Perf/Event/Heartbeat 조회를 건너뜁니다.")
        # 자율 발견 루프: 컴퓨터 이름만으로는 연결된 Log Analytics 워크스페이스를 유도할 수 없다.
        report.request_input(
            "workspace_id",
            "CPU/메모리/디스크/이벤트 로그를 읽으려면 Log Analytics 워크스페이스 GUID가 필요합니다.",
            "Resource Graph: resources | where type =~ 'microsoft.operationalinsights/workspaces' "
            "| project name, id, customerId = properties.customerId, resourceGroup",
            "windows-diagnose --computer <컴퓨터명> --workspace-id <Log Analytics GUID> --format json")

    # azure-monitor 모드는 대상이 Azure/Arc 문맥이 이미 확실하므로 resource_id도 적극 안내한다.
    _maybe_control_plane(report, args, nag_if_missing=(cred is not None))

    evaluate(report, data, thr)
    return report


def build_report_direct(args, thr: dict) -> Report:
    host = args.host or args.computer
    if not host:
        raise SystemExit("--host 는 필수입니다(--source direct, 또는 --demo)")
    if not args.winrm_user:
        raise SystemExit("--winrm-user 는 필수입니다(--source direct)")

    report = Report(computer=host, collection_mode="direct",
                    generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    window=f"last {args.hours}h")

    if args.winrm_cert_validation == "ignore":
        report.add("security", "warning", "WinRM 인증서 검증 비활성화",
                   "--winrm-cert-validation ignore 로 실행되어 TLS 인증서를 검증하지 않습니다. "
                   "중간자 공격(MITM)에 취약할 수 있습니다.",
                   recommendation="가능하면 신뢰할 수 있는 인증서를 사용하고 검증을 활성화하세요.")

    try:
        session = connect_winrm(args)
    except Exception as e:  # noqa: BLE001
        report.add("connection", "critical", "WinRM 연결 실패", str(e),
                  recommendation="호스트/포트/자격 증명/방화벽/WinRM 활성화 상태를 확인하세요 "
                                 "(Enable-PSRemoting -Force).")
        evaluate(report, {}, thr)
        return report
    report.sources.append("winrm")
    report.add("connectivity", "ok", "WinRM 연결 정상", f"{host} 에 연결했습니다.")

    data: dict[str, Any] = {}
    steps = [("cpu", lambda: collect_cpu_direct(session)),
            ("memory", lambda: collect_memory_direct(session)),
            ("disk", lambda: collect_disk_direct(session)),
            ("log_errors", lambda: collect_event_errors_direct(session, args.hours)),
            ("shutdown", lambda: collect_shutdown_direct(session, args.hours)),
            ("services", lambda: collect_services_direct(session)),
            ("roles_features", lambda: collect_roles_features_direct(session))]
    if args.skip_patch_check:
        report.add("patch", "info", "패치 점검 생략",
                  "--skip-patch-check 지정으로 생략했습니다(Windows Update 검색 부하 방지).")
    else:
        steps.append(("update", lambda: collect_update_direct(session)))
    if args.skip_upgrade_check:
        report.add("os_lifecycle", "info", "업그레이드 준비도 점검 생략",
                  "--skip-upgrade-check 지정으로 생략했습니다(설치 프로그램 전체 목록 조회 부하 방지).")
    else:
        steps.append(("os_info", lambda: collect_os_info_direct(session)))
        steps.append(("tpm_sb", lambda: collect_tpm_secureboot_direct(session)))
        steps.append(("software", lambda: collect_installed_software_direct(session)))
    for key, fn in steps:
        try:
            data[key] = fn()
        except Exception as e:  # noqa: BLE001
            report.add(key, "info", f"{key} 조회 실패", str(e))

    # direct 모드는 대상이 Azure VM인지 알 수 없으므로 resource_id를 강요하지 않는다
    # (사용자가 알고 있다면 --resource-id로 선택적으로 넘길 수 있다).
    _maybe_control_plane(report, args, nag_if_missing=False)

    evaluate(report, data, thr)
    return report


def build_report(args) -> Report:
    thr = _thresholds(args)

    if args.demo:
        report, data = build_demo_report(args.hours)
        evaluate(report, data, thr)
        return report

    if args.source == "direct" and (args.start_time or args.end_time):
        raise SystemExit("--start-time/--end-time 은 direct 모드에서는 지원되지 않습니다 "
                         "(WinRM은 대상 서버의 현재 시점 상태만 조회할 수 있습니다).")
    if args.end_time and not args.start_time:
        raise SystemExit("--end-time 은 --start-time 과 함께 지정해야 합니다.")

    if args.source == "direct":
        return build_report_direct(args, thr)
    return build_report_azure_monitor(args, thr)


def _emit(report: Report, args) -> None:
    # report-publish 연동(선택, opt-in) — REPORT_STORAGE_ACCOUNT가 설정된 경우에만 게시.
    import os
    if os.getenv("REPORT_STORAGE_ACCOUNT"):
        try:
            from report_publish import publish
            _pub_html = render_html(report)
            publish(_pub_html, kind="windows", resource=report.computer,
                   health_score=report.health_score())
        except Exception:
            pass

    if args.save_snapshot:
        # 시계열 이력 구축(사용자가 직접 cron/작업 스케줄러로 주기 실행 시): JSON Lines로 append.
        try:
            snap = _report_payload(report)
            snap["captured_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with open(args.save_snapshot, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(snap, ensure_ascii=False) + "\n")
        except Exception as e:  # noqa: BLE001
            print(f"[warn] --save-snapshot 저장 실패: {e}", file=sys.stderr)

    if args.format == "json":
        rendered = render_json(report)
    elif args.format == "html":
        rendered = render_html(report)
    else:
        rendered = render_table(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"Output written to {args.output}")
    else:
        print(rendered)


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = build_report(args)
    _emit(report, args)
    if args.exit_code:
        worst = report.worst_severity()
        return 2 if worst == "critical" else 1 if worst == "warning" else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
