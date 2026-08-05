**한국어** | [English](README.en.md)

# 🚀 windows_diagnose

**Windows 서버 읽기 전용(read-only) OS 진단 프로그램 — 온프레미스/Azure/AWS/GCP 등 어디서든 Azure Arc로 통합 관리**

대상 Windows 서버의 CPU/메모리/디스크/에이전트 연결/이벤트 로그/패치 상태를 진단하는 도구입니다. `pg_diagnose` / `aks_diagnose` / `adx_diagnose` / `eh_diagnose` / `agw_diagnose` / `svcmap_diagnose` / `linux_diagnose`와 동일한 진단 도구 제품군의 일원이며, 동일한 설계 철학(엄격한 read-only, JSON/HTML/table 출력, `health_score`/`summary`/`recommended_actions`)을 그대로 따릅니다.

## ✅ 권장 사용 방식 — Azure Arc 연결

이 도구는 기본적으로 **Azure Monitor Agent 원격 측정(Log Analytics)**을 읽기 전용 KQL로 조회하도록 설계되었습니다. 온프레미스/AWS/GCP 서버는 [Azure Arc-enabled servers](https://learn.microsoft.com/azure/azure-arc/servers/overview)로 온보딩하면(`azcmagent connect`), Azure VM과 동일하게 Azure Monitor Agent를 설치하고 Log Analytics workspace로 원격 측정을 보낼 수 있습니다 — 즉 **Arc 연결이 이 도구의 "정식 지원 경로"의 전제 조건**입니다.

```bash
python windows_diagnose.py --computer WIN-APP01 --workspace-id <workspace-guid> \
  --resource-id /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.HybridCompute/machines/WIN-APP01
```

`--resource-id`에 Arc 머신(`Microsoft.HybridCompute/machines`) 또는 Azure VM(`Microsoft.Compute/virtualMachines`) 리소스 ID를 지정하면, 두 유형 모두에 대해 제어 평면 정보(Arc는 에이전트 연결 상태, Azure VM은 전원 상태)를 자동으로 조회합니다.

## 🔒 숨은 옵션 — Azure Arc를 연결할 수 없는 경우

방화벽·정책·조직 사정 등으로 Azure Arc를 연결할 수 없는 예외적인 환경을 위해, **WinRM으로 직접 접속해 수집하는 `--source direct` 옵션도 내부적으로 지원**합니다. 이 옵션은 일반 사용자에게 권장하는 경로가 아니므로 `--help`에는 표시되지 않지만, 아래처럼 명시적으로 지정하면 그대로 동작합니다.

```bash
# --help에는 나오지 않지만 실제로 동작하는 숨은 옵션
$env:WINDOWS_DIAGNOSE_WINRM_PASSWORD = "..."
python windows_diagnose.py --source direct --host WIN-ONPREM01 --winrm-user diag_reader --format table
```

| | `--source azure-monitor` (기본, 정식 지원) | `--source direct` (숨은 옵션, Arc 미연결 시) |
|---|---|---|
| 무엇을 읽나 | 이미 수집된 Azure Monitor Agent 원격 측정(Log Analytics) | WinRM으로 접속해 실시간 PowerShell/CIM 명령 실행 결과 |
| 필요 조건 | **Azure Arc 온보딩**(또는 Azure VM) + Azure Monitor Agent + Log Analytics workspace | WinRM 접근 가능(`Enable-PSRemoting`) |
| 노출 여부 | `--help`에 표시됨(권장 경로) | `--help`에 숨김(문서에서만 안내) |
| 서버 변경 여부 | 없음(질의만) | 없음(읽기 전용 CIM/Get-WinEvent만 실행, WinRM으로 새 에이전트 설치 없음) |

전체 옵션(`--winrm-user`, `--winrm-password-env`, `--winrm-transport`, `--winrm-use-ssl`, `--winrm-cert-validation`, `--skip-patch-check` 등)은 이 문서 하단 "숨은 옵션 상세"를 참고하세요.

- 👉 CPU / 메모리 / 디스크 여유공간 / 에이전트(또는 WinRM) 연결 상태 / 이벤트 로그 오류 / 예기치 않은 재시작 / 패치 준수 상태를 진단합니다.
- 👉 Azure SRE Agent 및 MCP Tool 통합을 지원합니다.
- 👉 `--resource-id` 지정 시(Azure VM 또는 Arc 머신, 두 수집 방식 공통) 제어 평면 정보도 함께 조회합니다.

주요 진단 항목:

| 📋 항목 | 📋 항목 |
|---|---|
| 에이전트(또는 WinRM) 연결 상태 | CPU 사용률 |
| 메모리 사용률 | 디스크 여유공간 |
| 이벤트 로그 Error/Critical 건수 | 예기치 않은 종료/재시작 |
| 보안 업데이트 누락 | VM/Arc 머신 연결·전원 상태, 크기, OS 버전(선택, ARM) |

---

## 데이터 소스

### `--source azure-monitor` (모두 읽기 전용 KQL 질의 / ARM 조회)

| # | 소스 | 무엇을 읽나 | 테이블/질의 |
|---|------|------------|------|
| 1 | **Heartbeat** | 에이전트 연결 상태(마지막 하트비트 간격) | `Heartbeat` |
| 2 | **Perf** | CPU/메모리/디스크 사용률 | `Perf` (`Processor`, `Memory`, `LogicalDisk`) |
| 3 | **Event** | System/Application 이벤트 로그 Error/Critical, 예기치 않은 종료 | `Event` (EventLevelName, EventID 41/6008) |
| 4 | **Update** | 패치 준수 상태(Update Management 활성화 시) | `Update` |
| 5 | **ARM(선택)** | VM 또는 Arc 머신의 연결·전원 상태/크기/OS 버전(제어 평면) | `azure-mgmt-compute`(Azure VM) 또는 `azure-mgmt-hybridcompute`(Arc) |

`--computer`(Log Analytics `Computer` 컬럼 값)와 `--workspace-id`(Log Analytics workspace GUID)가 **필수**입니다.

```text
   --computer + --workspace-id ──▶ Heartbeat/Perf/Event/Update KQL (데이터 평면)
   --resource-id (선택, Azure VM 또는 Arc 머신) ──▶ azure-mgmt-compute 또는
                                        azure-mgmt-hybridcompute instanceView (제어 평면)
                                    └─▶ 병합 → OS 진단 리포트
```

### `--source direct` (숨은 옵션 — Azure Arc 연결 불가 시, WinRM으로 직접 접속)

| # | 소스 | 무엇을 읽나 | 명령 |
|---|------|------------|------|
| 1 | CPU | 프로세서 평균 부하율 | `Get-CimInstance Win32_Processor` (`LoadPercentage`) |
| 2 | 메모리 | 전체 대비 사용률 | `Get-CimInstance Win32_OperatingSystem` (`TotalVisibleMemorySize`/`FreePhysicalMemory`) |
| 3 | 디스크 | 드라이브별 여유공간 | `Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"` |
| 4 | 이벤트 로그 | System/Application Error/Critical 건수 | `Get-WinEvent -FilterHashtable` (Level 1,2) |
| 5 | 예기치 않은 종료 | Kernel-Power(41)/EventLog(6008) | `Get-WinEvent -FilterHashtable` (Id 41,6008) |
| 6 | 패치 | 보안 업데이트 대기 건수(최선다) | Windows Update Agent COM(`Microsoft.Update.Session`, 별도 모듈 불필요) |

`--host`(미지정 시 `--computer` 값 사용)와 `--winrm-user`가 **필수**입니다. Azure Monitor/Log Analytics workspace가 전혀 없어도 동작합니다 — 이것이 온프레미스·AWS·GCP 서버 지원의 핵심입니다.

**계정 분리와 동일한 철학**: WinRM 비밀번호는 CLI 인자로 절대 받지 않습니다 — `--winrm-password-env`로 지정한 환경변수(기본 `WINDOWS_DIAGNOSE_WINRM_PASSWORD`)에서 읽거나, 대화형 터미널이면 프롬프트로 입력받습니다. `--winrm-transport {ntlm(기본),kerberos,credssp,basic}`과 `--winrm-use-ssl`(HTTPS/5986)로 환경에 맞게 조정하세요.

**보안(인증서 검증)**: 기본값은 `--winrm-cert-validation validate`입니다. `ignore`(자체 서명 인증서 테스트 환경 전용, MITM 위험)로 설정하면 리포트에 보안 경고가 표시됩니다.

```text
   --host + --winrm-user (+ 비밀번호) ──▶ WinRM 접속
                                          └─▶ CIM/Get-WinEvent 등 읽기 전용 PowerShell → OS 진단 리포트
   --resource-id (선택, Azure VM 또는 Arc 머신) ──▶ azure-mgmt-compute/azure-mgmt-hybridcompute (제어 평면)
```

---

## ⚡ `--source direct`의 대상 서버 부하

direct 모드는 대상 서버에서 명령을 실행하므로 "부하가 얼마나 되는지"가 중요합니다. 결론: **한 번 실행할 때마다 짧은 CIM/이벤트 조회 5개를 순차 실행하는 수준(대부분 수십~수백 ms)이며, 지속적으로 폴링하는 모니터링 에이전트가 아닙니다.**

| 명령 | 부하 수준 | 비고 |
|---|---|---|
| `Get-CimInstance Win32_Processor`(CPU) | 매우 낮음 | 단일 WMI 스냅샷 조회 |
| `Get-CimInstance Win32_OperatingSystem`(메모리) | 매우 낮음 | 단일 WMI 스냅샷 조회 |
| `Get-CimInstance Win32_LogicalDisk`(디스크) | 매우 낮음 | 단일 WMI 스냅샷 조회 |
| `Get-WinEvent -FilterHashtable`(이벤트 로그) | 낮음~보통 | 필터가 공급자 단에서 적용되어 효율적이나, 창(시간범위) 내 이벤트가 매우 많으면 다소 걸릴 수 있음 |
| Windows Update Agent COM `Search()`(패치 점검) | **보통~높음** | WSUS/Windows Update에 **네트워크로 접속해 업데이트 메타데이터를 조회**하므로 다른 명령보다 훨씬 느리고(수십 초 이상 가능) 검색 중 일시적으로 CPU를 사용합니다 |

가장 부하가 큰 항목은 **패치 점검(Windows Update Agent 검색)**입니다. 운영 환경에서 반복 진단 시 이 부담을 피하고 싶다면 `--skip-patch-check`로 건너뛸 수 있습니다:

```bash
python windows_diagnose.py --source direct --host WIN-ONPREM01 --winrm-user diag_reader --skip-patch-check
```

패치 점검을 제외한 나머지 명령은 모두 WMI/이벤트 로그의 단일 스냅샷 조회이므로 대상 서버에 미치는 영향이 미미합니다.

---

## ⚙️ 설치

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

`--source direct`는 `pywinrm`을 사용합니다. 대상 Windows 서버에서 WinRM이 활성화되어 있어야 합니다(`Enable-PSRemoting -Force`).

> [!TIP]
> **Windows note.** 실행 전 `$env:PYTHONIOENCODING="utf-8"` 를 설정하세요(테이블 렌더러의 `UnicodeEncodeError` 방지).

---

## 🧰 사용법

```bash
# [azure-monitor] 기본 진단 (table)
python windows_diagnose.py --computer WIN-APP01 --workspace-id <workspace-guid>

# [azure-monitor] VM 제어 평면(전원 상태/크기)까지 포함
python windows_diagnose.py --computer WIN-APP01 --workspace-id <workspace-guid> \
  --resource-id /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/WIN-APP01

# [direct] 온프레미스/AWS/GCP 등 Azure Monitor 없이 WinRM으로 직접 진단
$env:WINDOWS_DIAGNOSE_WINRM_PASSWORD = "..."
python windows_diagnose.py --source direct --host WIN-ONPREM01 --winrm-user diag_reader --format table

# [direct] HTTPS(5986) + Kerberos
python windows_diagnose.py --source direct --host win01.corp.local --winrm-user diag_reader@CORP.LOCAL \
  --winrm-transport kerberos --winrm-use-ssl

# 임계값 조정 (두 방식 공통)
python windows_diagnose.py --computer WIN-APP01 --workspace-id <guid> \
  --cpu-warn 75 --cpu-crit 90 --disk-free-warn 20 --disk-free-crit 10

# JSON 출력 + CI용 exit code
python windows_diagnose.py --computer WIN-APP01 --workspace-id <guid> --format json --exit-code

# HTML 리포트 파일로 저장
python windows_diagnose.py --computer WIN-APP01 --workspace-id <guid> --format html -o windows_report.html

# 데모 데이터로 미리보기 (연결 없음)
python windows_diagnose.py --demo --format table
```

---

## 🧰 조회 기간 선택 & 이력 저장

**"1주일치", "1일치" 같은 기간을 직접 고를 수 있습니다** — azure-monitor 모드에서 두 가지 방식을 지원합니다.

| 방식 | 예시 | 비고 |
|---|---|---|
| 상대 기간 `--hours` (기본) | `--hours 24`(1일), `--hours 168`(1주일), `--hours 720`(30일) | 항상 "지금부터 N시간 전"까지 |
| 절대 기간 `--start-time`/`--end-time` | `--start-time 2026-07-28T00:00:00Z --end-time 2026-07-30T00:00:00Z` | 특정 날짜 구간(예: 지난주 월~수)을 정확히 지정 |

```bash
# 지난주 특정 3일 구간만 조회
python windows_diagnose.py --computer WIN-APP01 --workspace-id <guid> \
  --start-time 2026-07-28T00:00:00Z --end-time 2026-07-31T00:00:00Z --format html -o last_week.html
```

**direct 모드(WinRM)는 대상 서버의 "지금 이 순간" 상태만 조회할 수 있어 과거 날짜 조회가 불가능합니다** (`--start-time`/`--end-time`과 함께 쓰면 오류 반환). 대신 **`--save-snapshot <경로>`**로 실행할 때마다 결과를 JSON Lines 파일에 이어붙일 수 있습니다 — 이를 작업 스케줄러/cron으로 주기 실행(예: 매시간)하면, 직접 시계열 이력을 축적해 나중에 비교·추세 분석을 할 수 있습니다.

```bash
# 매시간 실행되도록 작업 스케줄러에 등록 → 스스로 이력을 쌓음
python windows_diagnose.py --source direct --host WIN-ONPREM01 --winrm-user diag_reader `
  --format json --save-snapshot C:\diag-history\win-onprem01.jsonl
```

---

## 🧰 진단 규칙 (Diagnostic Rules)

| Category | Signal | Warning | Critical | 계산식 / 비고 |
|----------|--------|---------|----------|---------------|
| `connectivity` | Heartbeat 간격 | ≥ `--heartbeat-warn-min`(기본 15분) | ≥ `--heartbeat-crit-min`(기본 60분) | `now - last_heartbeat` |
| `cpu` | 평균 % Processor Time | ≥ `--cpu-warn`(기본 80%) | ≥ `--cpu-crit`(기본 95%) | `Perf` 창 평균 |
| `memory` | 평균 % Committed Bytes In Use | ≥ `--mem-warn`(기본 85%) | ≥ `--mem-crit`(기본 95%) | `Perf` 창 평균 |
| `disk` | 최소 % Free Space(드라이브별) | ≤ `--disk-free-warn`(기본 15%) | ≤ `--disk-free-crit`(기본 5%) | 가장 여유공간이 적은 드라이브 |
| `eventlog` | Error/Critical 이벤트 건수 | ≥ `--log-err-warn`(기본 10건) | ≥ `--log-err-crit`(기본 50건) | 창 내 합계 |
| `stability` | Kernel-Power(41)/EventLog(6008) | — | 1건 이상 = critical | 예기치 않은 종료/재시작 |
| `patch` | 보안 업데이트 누락 건수 | 1건 이상 | 10건 이상 | `Update` 테이블(Update Management) |
| `control_plane` | VM 전원 상태 | — | Deallocated/Stopped = critical | ARM instanceView(선택) |

모든 항목은 데이터가 없으면 숨기지 않고 **"미평가"**로 표시됩니다(다른 도구와 동일한 리포트 완결성 철학).

---

## 🧰 출력 스키마 (Output Schema)

다른 도구와 동일한 `category` + `severity` 스키마를 사용하며, 최상위에 `summary`/`health_score`/`severity_counts`/`recommended_actions`/`needs_input`이 포함됩니다.

| 모드 | 내용 |
|---|---|
| `--format table` (기본) | 사람이 읽기 쉬운 텍스트 테이블 |
| `--format json` | `checks[]` 스키마 JSON (SRE Agent / MCP 연동용) |
| `--format html` | 요약 카드 + 진단표 (`-o`로 파일 저장) |

- `--exit-code` 지정 시 CI용 종료코드 반환(critical=2, warning=1, 그 외 0)

### 샘플 출력

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
      "title": "디스크 여유공간 부족: C:",
      "detail": "여유공간 3.2% (기준 critical ≤ 5.0%).",
      "recommendation": "C: 드라이브의 불필요한 파일/로그를 정리하거나 볼륨을 확장하세요."
    }
  ],
  "health_score": 62,
  "severity_counts": {"critical": 1, "warning": 1, "info": 0, "ok": 5},
  "summary": "건강 점수 62/100 (위험). WIN-APP01, last 24h (위험 1, 주의 1, 정보 0).",
  "worst_severity": "critical"
}
```

---

## 🧰 자율 발견 → 재호출 루프 (needs_input)

`--source azure-monitor`에서 `--workspace-id`가 없으면 필수값으로 안내되고, `--resource-id`가 없으면(어느 모드든) 선택값으로 안내됩니다 — 결과 JSON의 최상위 `needs_input`에 필요한 값과 `discovery_hint`(Resource Graph KQL 예시), `reinvoke_example`(재호출 명령 예시)가 채워집니다. `--source direct`는 온프레미스/AWS/GCP일 수있어 resource_id가 실재하지 않을 수 있으므로 **강요하지 않습니다**(사용자가 알고 있으면 직접 `--resource-id`로 전달 가능). Azure SRE Agent는 이를 참고해 값을 확정한 뒤 도구를 재호출할 수 있습니다.

---

## 🧰 MCP / Azure SRE Agent 통합

`mcp_server.py`에 `diagnose_windows_os` 도구로 등록되어 있습니다(pg/aks/adx/eh/agw/svcmap와 동일 패턴, `_run()` 공통 래퍼로 타임아웃/실패를 구조화 JSON으로 반환). `source` 파라미터로 `azure-monitor`/`direct`를 선택하며, `direct`일 때는 `host`/`winrm_user`를 전달합니다(비밀번호는 MCP 인자로 전달되지 않으며, MCP 컨테이너에 `WINDOWS_DIAGNOSE_WINRM_PASSWORD` 환경변수가 미리 준비돼 있어야 함).

Managed Identity에 다음 RBAC를 부여하면 됩니다(azure-monitor 모드 및/또는 제어 평면 사용 시).

- **Log Analytics workspace**: `Log Analytics Reader` (Perf/Event/Heartbeat/Update 조회)
- **VM(선택, `--resource-id` 사용 시)**: `Reader` (instanceView 조회)

`direct` 모드는 Azure 권한과 무관하며, 대상 서버에 WinRM으로 접속할 수 있는 계정(읽기 전용 권한 권장)만 있으면 됩니다.

---

## 한계 / 정확성 주의

- Arc-enabled server(Microsoft.HybridCompute)는 현재 버전에서 제어 평면 조회를 지원하지 않습니다(Azure VM만 지원). 데이터 평면(Perf/Event/Heartbeat 또는 WinRM 직접 수집)은 Arc 서버도 동일하게 동작합니다.
- `--source azure-monitor`: `Update` 테이블은 Update Management(또는 Azure Update Manager) 온보딩이 되어 있어야 채워집니다. 미온보딩 시 "미평가"로 표시됩니다.
- `--source direct`: Windows Update Agent COM 검색은 WSUS/인터넷 연결 상태에 따라 느릴 수 있으며, 실패하면 조용히 "미평가"로 폴백됩니다(진단 자체는 멈춰리지 않음).
- 원격 명령 실행(Run Command 등)은 사용하지 않습니다 — azure-monitor 모드는 이미 수집된 원격 측정만 읽고, direct 모드도 읽기 전용 CIM/Get-WinEvent 명령만 실행합니다.
