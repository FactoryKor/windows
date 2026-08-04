#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
windows_diagnose.py — Windows OS read-only diagnostic CLI (Azure VM / Arc server).

Part of the Azure diagnostic tool suite (pg / aks / adx / eh / agw / svcmap).
Design mirrors svcmap_diagnose: strict READ-ONLY, JSON/HTML/table output,
health_score / summary / recommended_actions for the SRE Agent / MCP path.

What it does
------------
대상 Windows 서버(Azure VM 또는 Arc-enabled server)의 OS 계층 상태를 진단한다.
CPU/메모리/디스크는 이미 수집돼 있는 Azure Monitor Agent 원격 측정(Perf 테이블)을
읽기 전용 KQL로 조회하며, 에이전트에 새 명령을 내리거나 원격 접속(SSH/WinRM)을
하지 않는다 — 다른 도구들과 동일하게 "이미 있는 데이터를 읽기만" 하는 설계다.

데이터 소스 (모두 읽기 전용 KQL 질의, Log Analytics workspace)
  1. Heartbeat     : 에이전트 연결 상태(마지막 하트비트 간격)
  2. Perf          : CPU(Processor/% Processor Time), 메모리(Memory/% Committed
                     Bytes In Use), 디스크 여유공간(LogicalDisk/% Free Space)
  3. Event         : System/Application 이벤트 로그의 Error/Critical 발생 건수,
                     예기치 않은 종료(Kernel-Power 41 / EventLog 6008)
  4. Update        : Update Management 패치 준수 상태(선택, 미설치 시 미평가)
  5. (선택) ARM 제어 평면: azure-mgmt-compute로 VM 전원 상태/크기/OS 버전 조회
                          (--resource-id 지정 시)

모든 동작은 조회(.query / instanceView read)만 수행하며 어떤 리소스도 변경하지 않는다.

Windows note: set  $env:PYTHONIOENCODING="utf-8"  before running if the table
renderer raises UnicodeEncodeError.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
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
}

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
SEV_LABEL_KO = {"critical": "위험", "warning": "주의", "info": "정보", "ok": "양호"}


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
# KQL (read-only queries against Log Analytics)
# --------------------------------------------------------------------------- #
_HEARTBEAT_KQL = """
Heartbeat
| where Computer =~ "{computer}"
| where TimeGenerated > ago({hours}h)
| summarize last_heartbeat = max(TimeGenerated), samples = count()
"""

_PERF_KQL = """
Perf
| where Computer =~ "{computer}"
| where TimeGenerated > ago({hours}h)
| where ObjectName == "{obj}" and CounterName == "{counter}"
{instance_clause}
| summarize avg_val = avg(CounterValue), max_val = max(CounterValue) by InstanceName
| order by avg_val desc
"""

_EVENT_ERR_KQL = """
Event
| where Computer =~ "{computer}"
| where TimeGenerated > ago({hours}h)
| where EventLevelName in ("Error", "Critical")
| summarize count() by EventLog, EventLevelName
"""

_EVENT_SHUTDOWN_KQL = """
Event
| where Computer =~ "{computer}"
| where TimeGenerated > ago({hours}h)
| where EventID in (41, 6008)
| summarize cnt = count(), sample = any(RenderedDescription)
"""

_UPDATE_KQL = """
Update
| where Computer =~ "{computer}"
| where TimeGenerated > ago({hours}h)
| where UpdateState == "Needed" and Optional == false
| summarize count() by Classification
"""

RID_PARSE = re.compile(
    r"^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/"
    r"Microsoft\.Compute/virtualMachines/([^/]+)$", re.IGNORECASE)


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


def _query(cred, workspace_id: str, kql: str, hours: int):
    from datetime import timedelta
    client = _logs_client(cred)
    return _rows(client.query_workspace(workspace_id, kql, timespan=timedelta(hours=hours)))


# --------------------------------------------------------------------------- #
# Collection (read-only)
# --------------------------------------------------------------------------- #
def collect_heartbeat(report: Report, cred, workspace_id: str, computer: str, hours: int) -> Optional[dict]:
    rows = _query(cred, workspace_id, _HEARTBEAT_KQL.format(computer=computer, hours=hours), hours)
    report.sources.append("heartbeat")
    if not rows or rows[0].get("last_heartbeat") is None:
        return None
    last = rows[0]["last_heartbeat"]
    if isinstance(last, str):
        last = datetime.fromisoformat(last.replace("Z", "+00:00"))
    gap_min = (datetime.now(timezone.utc) - last).total_seconds() / 60.0
    return {"last": last.isoformat(), "gap_min": gap_min, "samples": int(rows[0].get("samples") or 0)}


def collect_perf(cred, workspace_id: str, computer: str, hours: int,
                 obj: str, counter: str, instance_only: str = "") -> list[dict]:
    clause = f'| where InstanceName == "{instance_only}"' if instance_only else ""
    kql = _PERF_KQL.format(computer=computer, hours=hours, obj=obj, counter=counter,
                          instance_clause=clause)
    return _query(cred, workspace_id, kql, hours)


def collect_event_errors(cred, workspace_id: str, computer: str, hours: int) -> list[dict]:
    return _query(cred, workspace_id, _EVENT_ERR_KQL.format(computer=computer, hours=hours), hours)


def collect_shutdown_events(cred, workspace_id: str, computer: str, hours: int) -> Optional[dict]:
    rows = _query(cred, workspace_id, _EVENT_SHUTDOWN_KQL.format(computer=computer, hours=hours), hours)
    if not rows or not rows[0].get("cnt"):
        return None
    return {"count": int(rows[0]["cnt"]), "sample": str(rows[0].get("sample") or "")}


def collect_update(cred, workspace_id: str, computer: str, hours: int) -> list[dict]:
    return _query(cred, workspace_id, _UPDATE_KQL.format(computer=computer, hours=hours), hours)


def collect_vm_control_plane(report: Report, cred, resource_id: str) -> None:
    m = RID_PARSE.match(resource_id or "")
    if not m:
        report.add("control_plane", "info", "VM 제어 평면 미평가",
                   "resource_id가 Microsoft.Compute/virtualMachines 형식이 아니어서 "
                   "건너뜁니다(Arc-enabled server는 현재 버전에서 미지원).")
        return
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
        "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
        "os_type": os_type,
        "power_state": power_state,
        "location": vm.location,
    }
    report.sources.append("compute:instanceView")


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


def evaluate_control_plane(report: Report) -> None:
    if not report.vm_info:
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
    evaluate_connectivity(report, data.get("heartbeat"), thr)
    evaluate_cpu(report, data.get("cpu") or [], thr)
    evaluate_memory(report, data.get("memory") or [], thr)
    evaluate_disk(report, data.get("disk") or [], thr)
    evaluate_logs(report, data.get("log_errors") or [], thr)
    evaluate_shutdown(report, data.get("shutdown"))
    evaluate_update(report, data.get("update") or [])
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


def render_json(report: Report) -> str:
    payload = _clean(asdict(report))
    payload["worst_severity"] = report.worst_severity()
    payload["health_score"] = report.health_score()
    payload["severity_counts"] = report.severity_counts()
    payload["summary"] = _clean(report.summary_text())
    payload["recommended_actions"] = _clean(report.recommended_actions())
    return json.dumps(payload, ensure_ascii=False, indent=2)


_SEV_TAG = {"critical": "[위험]", "warning": "[주의]", "info": "[정보]", "ok": "[양호]"}


def render_table(report: Report) -> str:
    counts = report.severity_counts()
    lines = [
        f"{TOOL_NAME} v{TOOL_VERSION}",
        f"대상     : {report.computer or '(미지정)'}",
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
  대상: <b>{_esc(report.computer or '(미지정)')}</b><br>
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
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Read-only Windows OS diagnostic tool (Azure Monitor Agent telemetry).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    src = p.add_argument_group("target (read-only KQL / ARM)")
    src.add_argument("--computer", help="Log Analytics 'Computer' column value (required unless --demo)")
    src.add_argument("--workspace-id", help="Log Analytics workspace GUID")
    src.add_argument("--resource-id", default="",
                     help="VM ARM resource id (optional control-plane: power state/size/OS)")

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

    out = p.add_argument_group("output")
    out.add_argument("--format", choices=["table", "json", "html"], default="table")
    out.add_argument("--output", "-o", help="Write report to this path instead of stdout")
    out.add_argument("--demo", action="store_true",
                     help="Use synthetic data (no Azure calls) to preview the report")
    out.add_argument("--exit-code", action="store_true",
                     help="Exit 2 if any critical, 1 if any warning, else 0")
    return p


def _thresholds(args) -> dict:
    return {"cpu_warn": args.cpu_warn, "cpu_crit": args.cpu_crit,
           "mem_warn": args.mem_warn, "mem_crit": args.mem_crit,
           "disk_free_warn": args.disk_free_warn, "disk_free_crit": args.disk_free_crit,
           "heartbeat_warn_min": args.heartbeat_warn_min, "heartbeat_crit_min": args.heartbeat_crit_min,
           "log_err_warn": args.log_err_warn, "log_err_crit": args.log_err_crit}


def build_report(args) -> Report:
    thr = _thresholds(args)

    if args.demo:
        report, data = build_demo_report(args.hours)
        evaluate(report, data, thr)
        return report

    if not args.computer:
        raise SystemExit("--computer 는 필수입니다(또는 --demo)")

    report = Report(computer=args.computer,
                    generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    window=f"last {args.hours}h")
    cred = None
    try:
        from azure.identity import DefaultAzureCredential
        cred = DefaultAzureCredential()
    except Exception as e:  # noqa: BLE001
        report.add("auth", "info", "Entra 자격 증명 사용 불가", str(e))

    data: dict[str, Any] = {}
    if cred is not None and args.workspace_id:
        try:
            data["heartbeat"] = collect_heartbeat(report, cred, args.workspace_id, args.computer, args.hours)
        except Exception as e:  # noqa: BLE001
            report.add("connectivity", "info", "Heartbeat 조회 실패", str(e))
        try:
            data["cpu"] = collect_perf(cred, args.workspace_id, args.computer, args.hours,
                                       "Processor", "% Processor Time", "_Total")
        except Exception as e:  # noqa: BLE001
            report.add("cpu", "info", "CPU Perf 조회 실패", str(e))
        try:
            data["memory"] = collect_perf(cred, args.workspace_id, args.computer, args.hours,
                                          "Memory", "% Committed Bytes In Use")
        except Exception as e:  # noqa: BLE001
            report.add("memory", "info", "메모리 Perf 조회 실패", str(e))
        try:
            data["disk"] = collect_perf(cred, args.workspace_id, args.computer, args.hours,
                                        "LogicalDisk", "% Free Space")
        except Exception as e:  # noqa: BLE001
            report.add("disk", "info", "디스크 Perf 조회 실패", str(e))
        try:
            data["log_errors"] = collect_event_errors(cred, args.workspace_id, args.computer, args.hours)
        except Exception as e:  # noqa: BLE001
            report.add("eventlog", "info", "Event 조회 실패", str(e))
        try:
            data["shutdown"] = collect_shutdown_events(cred, args.workspace_id, args.computer, args.hours)
        except Exception as e:  # noqa: BLE001
            report.add("stability", "info", "종료 이벤트 조회 실패", str(e))
        try:
            data["update"] = collect_update(cred, args.workspace_id, args.computer, args.hours)
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

    if cred is not None and args.resource_id:
        try:
            collect_vm_control_plane(report, cred, args.resource_id)
        except Exception as e:  # noqa: BLE001
            report.add("control_plane", "info", "VM 제어 평면 조회 실패", str(e))
    elif cred is not None and not args.resource_id:
        report.request_input(
            "resource_id",
            "VM 전원 상태/크기/OS 버전(제어 평면)을 확인하려면 ARM resource_id가 필요합니다.",
            "Resource Graph: resources | where type =~ 'microsoft.compute/virtualmachines' "
            "and name =~ '<computer>' | project name, id, resourceGroup, subscriptionId",
            "windows-diagnose --computer <컴퓨터명> --workspace-id <GUID> "
            "--resource-id /subscriptions/<sub>/resourceGroups/<rg>/providers/"
            "Microsoft.Compute/virtualMachines/<vm> --format json")

    evaluate(report, data, thr)
    return report


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
