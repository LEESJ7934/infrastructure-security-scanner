# Windows Server 기술적 보안 진단과 실습

이 문서는 초기 구현과 **Windows Server 2022 Standard Evaluation / build 20348 / Server Core 실습 결과**를 설명한다. 해당 환경의 실습은 사용자가 수행했고, 보완 작업에서는 저장된 JSON만 재분석했다. 2019/2025는 미검증 후보이며, 2022도 모든 역할·패치 수준에 대한 지원을 확정하지 않는다. 현재 Windows 데스크톱을 서버로 진단하지 않는다. 기존 Day1~5 결과, 수동 판정, 증적, PDF는 변경하지 않는다.

## 기준 출처와 한계

[KISA/KrCERT 공식 게시물](https://www.krcert.or.kr/kr/bbs/view.do?bbsId=B0000127&menuNo=205021&nttId=71928)에서 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」의 **2025-12-24 게시**를 확인했다. 이번 조사 환경에서는 첨부 다운로드가 PDF 대신 HTML을 반환하여 Windows 본문과 공식 항목 ID/판정 기준을 확인하지 못했다. 이전 판의 W-번호를 가져오거나 공식 기준을 추정하지 않았다.

`WIN-LAB-*`는 **내부 실습 기준**이며 `official_check_id=null`, 공식 매핑 `UNVERIFIED`다. WIN-LAB-002/003/004/009는 별도 기준 파일과 연결한 **v0.3**, WIN-LAB-005는 미설치 적용성을 다루는 v0.2, 나머지는 v0.1이다. 아래 수치와 목적·위험·조치 설명은 프로젝트 내부 선정 내용이다. KISA 원문 확보 후 목적/위험/양호·취약 기준/방법/조치/버전 적용성을 대조하고, 변경 시 규칙 버전을 올려 비교 호환성을 다시 검증해야 한다. 현재 결과를 KISA 적합성 인증으로 사용하지 않는다.

| 내부 ID | 목적 / 위험 | 설정 범위와 내부 양호 기준 | 확인 / 조치 검토 |
|---|---|---|---|
| WIN-LAB-001 | 불필요한 Guest 접근 축소 / 공유 계정 오용 | 로컬 SAM의 RID 501 계정 정확히 1개, 비활성 | Get-LocalUser로 이름 대신 RID 식별. 역할 검토 후 수동 비활성화 |
| WIN-LAB-002 | 짧은 암호 위험 축소 / 추측 공격 | 독립 서버 로컬 계정 최소 길이 14 이상 제안. 명시적 승인 필요 | secedit 병합 내보내기의 MinimumPasswordLength. 승인·수집값 없으면 REVIEW |
| WIN-LAB-003 | 단순 암호 위험 축소 | 독립 서버 로컬 복잡성 활성 | PasswordComplexity. 조직 정책과 암호 관리 방식 확인 |
| WIN-LAB-004 | 반복 로그인 공격 제한 / 잠금 DoS 고려 | 독립 서버 임계값 정확히 10회 제안. 기간·초기화 값은 승인 전 null | LockoutBadCount/LockoutDuration/ResetLockoutCount. 승인된 세 값을 모두 대조. 기본값 추정 금지 |
| WIN-LAB-005 | 불필요한 인쇄 서비스 공격면 축소 | **인쇄 불필요가 승인된 서버만** 설치된 Spooler 중지 및 Disabled. 검증된 미설치는 별도 적용성 판단 | CIM + SCM + 설치 역할 확인. 부재만으로 PASS 금지 |
| WIN-LAB-006 | 호스트 방화벽 비활성 위험 확인 | ActiveStore의 Domain/Private/Public 모두 Enabled, MpsSvc Running | Get-NetFirewallProfile -PolicyStore ActiveStore. 규칙·통신 허용 여부는 별도 시험 |
| WIN-LAB-007 | 레거시 SMB 프로토콜 노출 축소 | SMB 서버 EnableSMB1Protocol=false | Get-SmbServerConfiguration. 레거시 의존성 검토 후 수동 조치 |
| WIN-LAB-008 | SMB 서버 메시지 무결성 설정 확인 | SMB 서버 RequireSecuritySignature=true | 서버 수신 방향만 확인. 클라이언트 송신·실제 세션 협상은 별도 |
| WIN-LAB-009 | 감사 설정 탐지 사각 확인 | 5개 시스템 감사 GUID의 성공·실패 플래그를 승인 기준과 비교 | AuditQuerySystemPolicy 사용. 기존 실행 성공 플래그만으로 PASS 금지. 실제 이벤트 도달은 별도 |

### Microsoft 조회 인터페이스 근거

- [Get-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser?view=powershell-5.1): 64비트 OS의 32비트 PowerShell에는 LocalAccounts 모듈을 사용할 수 없다. DC의 로컬 SAM 점검은 NOT_APPLICABLE로 제외한다.
- [Win32_OperatingSystem](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem), [Win32_ComputerSystem](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem): ProductType/DomainRole/PartOfDomain으로 서버·독립/멤버/DC 구분. Caption의 Server 연도는 후보 식별, Version/BuildNumber는 관측값이며 빌드별 지원을 추정하지 않는다.
- [secedit /export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export): SECURITYPOLICY만 `/mergedpolicy`로 임시 내보내기. 도메인/로컬 병합 출력도 도메인 사용자 및 세분화 암호 정책(FGPP)의 유효성을 입증하지 않는다. 멤버/DC의 암호 점검은 NEEDS_REVIEW다.
- [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2025-ps): ActiveStore 결과를 사용한다. `NotConfigured`를 bool=true로 캐스팅하지 않는다.
- [Get-SmbServerConfiguration](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbserverconfiguration?view=windowsserver2025-ps), [SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing?tabs=powershell): 버전 기본값 대신 실제 필드를 읽는다. Server 2025의 송신 서명 기본값을 수신 서버 서명 의무화와 혼동하지 않는다.
- [auditpol /get](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get): 감사 정책 보안 설명자의 Read 권한이 필요하다. 출력이 언어별로 달라 현재 어댑터는 의미를 추정하지 않는다. 실행 성공만으로 감사 양호가 아니다.

## 구조와 안전 경계

- `config_audit/collectors/windows_server.py`: 명시적 JSON 한 파일만 읽기, 최대 1MiB, 중복 JSON 키/NaN/잘못된 타입/알 수 없는 필드 거부. 고정 오류 코드만 반환한다. 읽기 시 실제 SHA-256 계산, 독립 기대 해시 없으면 NOT_VERIFIED이며 설정을 PASS/FAIL로 확정하지 않는다. 불일치는 입력 ERROR로 거부한다.
- `AuditRule` 9개와 `Observation`을 기존 `evaluate()`에 전달한다. 별도 판정 엔진이나 AuditStatus 수정은 없다. 각 결과에 자산, 제품/연도/OS 버전/빌드, 규칙 버전, 범위, 판정, 수집 상태·오류 코드, 증적 식별자, 권고, collected_at, checked_at을 포함한다. 위험도는 공식/조직 매핑 미확인으로 부여하지 않는다.
- `scripts/run_windows_audit.py`: PowerShell·원격 연결을 실행하는 옵션이 없다. 기본 실행은 9개 NOT_TESTED와 준비 상태만 출력한다. 수집 시각은 원본 timezone을 유지하고 재분석 시각은 새 UTC checked_at/generated_at으로 구분한다.
- `scripts/collect_windows_server.ps1`: VM에서 운영자가 직접 실행한다. 기본 실행은 안내뿐이고 `-Execute`일 때만 CIM으로 제품을 확인한다. Server ProductType, 64비트 프로세스, 후보 연도를 확인한 뒤 조회한다. 출력 파일은 CreateNew로 생성하여 기존 증적을 덮어쓰지 않는다.
- 내보내기는 설정 변경이 아닌 **로컬 임시 파일 생성**이다. 계정명·전체 SID·원본 정책·원본 감사 CSV·암호·키·네이티브 오류 메시지는 JSON에 포함하지 않는다. SECURITYPOLICY 임시 파일과 로그는 finally에서 자신이 만든 정확한 경로만 정리한다. 정리 실패는 전체 수집 실패이며 로컬에서 잔여 파일을 안전하게 확인한다.
- 합성 입력은 origin=synthetic이며 CLI의 `--synthetic`이 필요하다. 결과는 `synthetic_results`에만 들어가고 실제 `results`는 빈 배열이다. 이 플래그는 실장비 검증을 의미하지 않는다.
- 증적 식별자는 `windows-evidence:<실제 파일 digest>#<section>`이다. SHA 일치는 진위·자산 동일성·완전성 증명이 아니다. 자산은 운영자가 가명 ID로 지정하고 승인된 VM과 연결한 이력을 별도로 보관해야 한다.

수집 오류는 ERROR, 미수집은 NOT_TESTED, 불완전 필드·알 수 없는 역할·도메인 유효 정책 미확인은 NEEDS_REVIEW다. 알려진 범위 밖 제품/연도와 DC 로컬 Guest, 승인된 인쇄 필수 역할은 NOT_APPLICABLE이다. 실제 관측값이 없는 필드를 거짓이나 0으로 채워 PASS/FAIL로 만들지 않는다. 미설치 Spooler도 조회 실패만으로 안전하다고 판단하지 않는다.

## 입력 JSON 계약 v1

필수 최상위 키는 schema_version=1, origin, asset_id, collected_at, system, sections다. 아래는 **미수집 템플릿**이며 실제 결과가 아니다. 수집 스크립트가 실제 값으로 생성한다. system의 os_version/build_number는 선택적 숫자 문자열이다.

```json
{
  "schema_version": 1,
  "origin": "synthetic",
  "asset_id": "WIN-LAB-SERVER",
  "collected_at": "2026-11-06T00:00:00+00:00",
  "system": {
    "server_release": "2022", "product_type": 3, "domain_role": 2,
    "part_of_domain": false, "is_64bit": true
  },
  "sections": {
    "guest": {"state": "NOT_TESTED"},
    "security_policy": {"state": "NOT_TESTED"},
    "spooler": {"state": "NOT_TESTED"},
    "firewall": {"state": "NOT_TESTED"},
    "smb": {"state": "NOT_TESTED"},
    "audit": {"state": "NOT_TESTED"}
  }
}
```

템플릿의 시각은 예시이며 실제 증적에 사용하지 않는다.

COLLECTED의 values 허용 키와 타입:

| 섹션 | 키 |
|---|---|
| guest | enabled:bool, matching_accounts:int |
| security_policy | minimum_length:int, complexity:bool, lockout_threshold:int, lockout_duration:int, reset_minutes:int, merged_policy:bool |
| spooler | 기존 required:bool, role_approval:승인 ID, running:bool, disabled:bool. 선택적 확장: present:bool, native_error_code:int, feature_query_state:고정 상태, feature_error_code:고정 오류 코드, print_services_installed/print_server_installed:bool |
| firewall | policy_store:"ActiveStore", domain/private/public/service_running:bool |
| smb | smb1_enabled/require_signing:bool |
| audit | 기존 parser_verified:bool 유지. 선택적 method:"AuditQuerySystemPolicy", subcategories:[{guid:문자열, mask:정수}] 추가. 실행 성공 플래그만으로 PASS 금지 |

값이 없으면 키 생략 또는 null로 기록한다. 문자열 "True"나 숫자 1을 bool로 허용하지 않는다. state는 COLLECTED/ERROR/NOT_TESTED/NOT_APPLICABLE만 허용하며 ERROR에는 permission_denied/command_unavailable/query_failed/parse_failed 중 고정 error_code를 기록한다. 상태와 값이 충돌하는 입력은 거부한다.

### Spooler 미설치와 조회 실패 구분 (v0.2)

1. Win32_Service 조회가 **성공**하고 Spooler가 0개인 경우에만 `sc.exe query Spooler`로 로컬 SCM을 대조한다. [Windows 오류 1060](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-)은 서비스 미설치를 뜻한다. CIM 빈 결과와 실제 SCM 종료 코드 1060이 함께 있을 때 `COLLECTED`, `present=false`, `native_error_code=1060`으로 기록한다. 문자열 오류 메시지나 빈 결과만으로 미설치를 추정하지 않는다.
2. CIM/서비스 명령 실패, SCM 접근 거부(5), 모순된 조회 결과 등은 ERROR다. 일반 query_failed를 1060으로 소급 변환하지 않는다.
3. 부재 확인 후 [Get-WindowsFeature](https://learn.microsoft.com/en-us/powershell/module/servermanager/get-windowsfeature)로 Print-Services/Print-Server를 별도 조회한다. Installed는 설치, Available/Removed는 미설치로 표준화한다. 역할 조회 실패는 `feature_query_state=ERROR`와 고정 `feature_error_code`로 분리하여 이미 확인한 서비스 부재를 지우지 않는다.
4. **서비스 부재 확인 + 두 인쇄 기능 미설치 확인 + 인쇄 불필요 승인 ID + 알려진 서버 역할 + 원본 해시 일치**를 만족해야 내부 기준에 따라 NOT_APPLICABLE이다. PASS를 만들지 않는다. 승인 없음/인쇄 필수/기능 조회 불완전/해시 미검증이면 NEEDS_REVIEW다.
5. 선택적 필드가 없는 기존 schema_version=1 JSON도 그대로 읽는다. 기존 `ERROR(query_failed)` 증적은 현재도 ERROR다. 원본 JSON에 미설치 필드를 수동 삽입하지 않고 **새 파일**로 재수집한다. 새 선택 필드를 읽으려면 보완된 Python 진단기를 함께 사용해야 한다.

### 실제 Server 2022 실습과 시각 한계

다음 두 파일은 로컬에 실제 존재하며, 보완 작업에서 제공된 기대 SHA-256과 일치를 확인했다. 이 일치는 파일 무결성 대조이며 수집 출처의 진위나 VM 시계의 정확성을 인증하지 않는다.

| 자료 | 원본 수집 시각 (원문 보존) | 제공된 기대 SHA-256 |
|---|---|---|
| logs/phase2-windows/windows-before.json | 2026-11-07T00:12:16.4773242+00:00 | 40dc965435b52a477d46a197cf0a4f6cdd8ba8ad1ddf490c8ceea2323a8c5e8a |
| logs/phase2-windows/windows-after.json | 2026-11-06T07:30:27.6763422+00:00 | 93939552c36deff4e5bf4981930f606d85f142f6829ee569c541c070d1db0f19 |

사용자 실습 기록에 따르면 최초 VM 시계가 약 17시간 빨랐고 재점검 전에 정상화했다. 정확한 오차값을 원본 시각에서 임의 차감하지 않았다. 설정 관찰은 WIN-LAB-008 **FAIL→PASS**, WIN-LAB-007 **PASS 유지**, WIN-LAB-005 **ERROR(query_failed) 유지**다. 최초 합계 PASS 3 / FAIL 1 / NEEDS_REVIEW 4 / ERROR 1, 개선 후 PASS 4 / NEEDS_REVIEW 4 / ERROR 1이다. 별도 콘솔에서 확인한 1060 및 인쇄 기능 Available은 사용자 제공 사실로 기록하고 과거 JSON 수집 결과를 덮어쓰지 않는다.

`config_audit/windows_comparison.py`의 `compare_windows_snapshots()`는 기존 공통 비교 엔진을 재사용하는 **Phase2 전용 엄격 시각 어댑터**다. 명시적인 전후 관계의 원본 `collected_at`을 비교하며, `checked_at`/`generated_at` 재분석 시각을 대신 사용하지 않는다. 원본 결과와 시각은 불변이다. 일반 공통 비교에 어댑터 없이 넘겨도 재분석 시각을 수집 시각으로 오인하지 않도록 time_basis=reanalysis_time을 기록한다.

- 정상 수집 순서 + 같은 자산/범위/규칙/방식 + 기존 증적 조건 충족: 기존 IMPROVED_OBSERVED 등 적용. 조치 이력 확정은 별도다.
- 분석 기준 시계보다 미래인 수집 또는 누락/시간대 미확인 시각: UNVERIFIABLE. 미래 판정 기준 시각은 분석 결과에 별도로 남긴다. 분석 시계 자체가 인증됐다고 주장하지 않는다.
- 최초 시각 ≥ 재점검 시각: INCOMPARABLE. 시간이 지난 뒤 최초 시각이 더 이상 미래가 아니어도 **역전은 그대로**다.
- 실제 두 파일은 역전되어 엄격 비교 INCOMPARABLE이다. WIN-LAB-008의 `recorded_status_transition=FAIL_TO_PASS`는 따로 보존하지만 개선 완료나 시간적으로 입증된 개선으로 계산하지 않는다.
- Phase2 전체 증적 인덱스 정책은 아직 미연동이므로 별도 인덱스가 없으면 그 제한도 기록한다. 수집기의 해시 일치 메타데이터로 인덱스 항목을 꾸며내지 않는다.

라이브러리 사용 예(로컬 기존 파일만 읽음):

```python
from config_audit.collectors.windows_server import load_bundle, audit, to_report_snapshot
from config_audit.reporting import OfflineReport
from config_audit.comparison import SnapshotRelation
from config_audit.windows_comparison import compare_windows_snapshots

# before/after_bundle은 각각 명시적 파일 경로와 독립 기대 해시로 load_bundle().
before = audit(before_bundle, asset_id=before_bundle.document["asset_id"])
after = audit(after_bundle, asset_id=after_bundle.document["asset_id"])
report = OfflineReport(after["generated_at"], (
    to_report_snapshot(before, snapshot_id="windows-before"),
    to_report_snapshot(after, snapshot_id="windows-after"),
))
comparison = compare_windows_snapshots(report, [SnapshotRelation("windows-before", "windows-after")])
```

### 보완 후 VM 재수집과 완료 기준

아래는 **사용자가 실제 Server VM 콘솔에서 실행할 명령**이다. 이번 보완 작업에서는 실행하지 않았다. 보완된 PowerShell/Python 파일을 함께 사용하고 기존 before/after 파일은 보존한다. VM의 현재 UTC 시각을 먼저 승인된 기준 시계와 대조하되, 수집기가 시간을 변경하지 않는다. 역할 승인 옵션은 실제 검토 완료 시에만 지정한다.

```powershell
# Server VM, 64비트 Windows PowerShell 5.1. 현재 시각을 읽기만 한다.
[DateTimeOffset]::UtcNow.ToString('o')
Get-WindowsFeature -Name Print-Services,Print-Server | Select-Object Name,InstallState
Get-CimInstance Win32_Service -Filter "Name='Spooler'" | Select-Object Name,State,StartMode
sc.exe query Spooler
.\scripts\collect_windows_server.ps1 -Execute -AssetId WIN-LAB-SERVER `
  -OutputPath C:\LabEvidence\windows-followup-spooler-v02.json `
  -SpoolerRequirement NotRequired -RoleApproval <실제-역할-검토-승인-ID>
Get-FileHash C:\LabEvidence\windows-followup-spooler-v02.json -Algorithm SHA256

# 분석 PC의 프로젝트 루트: 새 파일 전달 후, VM에서 별도 보관한 해시 사용
.\.venv\Scripts\python.exe -B -m scripts.run_windows_audit `
  --asset-id WIN-LAB-SERVER --input-json <새-수집본-로컬-경로> `
  --expected-sha256 <VM에서-별도-보관한-SHA256>
```

자산 ID는 최초 증적과 동일한 실제 승인 ID를 사용한다. 완료 조건은 새 JSON의 Spooler COLLECTED/부재 근거/별도 기능 조회 상태를 수동 조회와 대조하고, 역할 승인에 따라 NA 또는 REVIEW가 설명되는 것, 원본과 전달본 해시 대조 및 새 시각·기준 시계·자산 이력이 남는 것이다. 기존 ERROR를 PASS로 바꾸는 것이 완료 조건은 아니다. 시간 정상화 뒤 새로 수집한 두 스냅샷의 관계로 재점검하거나, 기존 역전 쌍의 제한을 계속 명시한다. 새 수집본도 설정 변경 없이 취득한다.

## 향후 VM 준비와 실행 순서

1. Server 2019/2022/2025 정식 평가/보유 라이선스 설치 ISO를 Microsoft 공식 경로에서 준비한다. 설치는 이번 작업 범위가 아니다. 초기 실습은 DC가 아닌 독립 Server 2022 후보를 권장한다. 예: 2 vCPU, RAM 4~8GB, 디스크 60GB 이상(내부 실습 권장값, 제품 최소 사양 아님). OS 패치 상태·언어·에디션·빌드와 스냅샷을 기록한다.
2. 격리 Internal/Host-only 스위치에 연결하고 기존 OPNsense 실습망이나 운영망과 혼용하지 않는다. 예시 별도 10.77.60.0/24에서 충돌 없는 주소를 사전 승인한다. WinRM/RDP/SSH 또는 외부 포트를 이 구현을 위해 자동 개방하지 않는다. VM 콘솔에서 실행한다.
3. 조회 권한을 개별 확인한다. 일반 사용자로 가능한 조회와 secedit/감사 보안 설명자 Read 등 제한된 조회를 구분한다. 도구별 실패는 ERROR로 남긴다. 격리 VM에서 승인된 관리자 콘솔이 필요할 수 있지만, 모든 운영 서버에 관리자 권한이 필수라고 단정하거나 자동 승격·권한 부여하지 않는다. PS 5.1 64비트와 각 모듈/명령 존재를 확인한다.
4. 수집 스크립트를 VM 안으로 검토 후 전달한다. ExecutionPolicy를 전역 완화하지 않고 조직 승인 서명/실행 절차를 따른다. 아래 **VM 안에서만** 실행하는 예에서 승인 ID는 비밀정보가 아닌 역할 검토 문서 식별자다. 인쇄 요구가 미확정이면 두 역할 옵션을 생략하여 NEEDS_REVIEW로 둔다.

```powershell
# VM 콘솔, 수동 실행. C:\LabEvidence 디렉터리는 운영자가 미리 준비한다.
.\scripts\collect_windows_server.ps1
.\scripts\collect_windows_server.ps1 -Execute -AssetId WIN-LAB-SERVER `
  -OutputPath C:\LabEvidence\windows-before.json `
  -SpoolerRequirement NotRequired -RoleApproval LAB-ROLE-01
Get-FileHash C:\LabEvidence\windows-before.json -Algorithm SHA256
```

5. 원본 파일의 해시를 **전달 전 VM에서 독립 보관**한다. 파일을 승인된 방식으로 로컬의 비공개 증적 폴더로 옮긴다. 스크립트는 해시를 기대값으로 자동 재사용하지 않는다. 다음은 프로젝트 루트의 Windows 가상환경 실행 예다. `<...>`는 실제 확인한 값으로 바꾸며 이 문서는 실제 증적 파일을 생성하지 않는다.

```powershell
Set-Location C:\Projects\infrastructure-security-scanner-clone
.\.venv\Scripts\python.exe -B -m scripts.run_windows_audit
.\.venv\Scripts\python.exe -B -m scripts.run_windows_audit `
  --asset-id WIN-LAB-SERVER --input-json <수집본-로컬-경로> `
  --expected-sha256 <전달-전-독립-보관한-64자리-SHA256>
.\.venv\Scripts\python.exe -B -m unittest tests.test_windows_audit
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
```

실제 수집이 없다면 기본 결과는 9개 NOT_TESTED다. 합성 테스트의 예측은 정상 내부 설정 8개 PASS, 감사 1개 NEEDS_REVIEW이며 **단위 테스트 시뮬레이션**으로만 사용한다. 해시를 생략한 저장본은 NOT_VERIFIED이고 PASS를 확정하지 않는다. JSON 문법/스키마/자산 바인딩/해시 오류는 고정 ERROR 코드와 종료 코드 2다.

6. 필요한 직접 확인 명령은 VM 콘솔의 `Get-LocalUser`, `Get-Service Spooler,MpsSvc`, `Get-NetFirewallProfile -PolicyStore ActiveStore`, `Get-SmbServerConfiguration`, `auditpol /get /category:* /r`다. 원본 화면/출력에는 계정명·호스트명 등이 있을 수 있어 공개 로그에 붙이지 않는다. 로컬 정책과 도메인 정책/FGPP를 별도로 검토한다. 감사 하위 범주의 GUID·언어·성공/실패와 실제 이벤트 발생을 확인해야 후속 자동화를 승인할 수 있다.
7. 조치가 필요하면 별도 변경 승인과 복구 계획을 수립한다. 이 코드는 조치하지 않는다. 승인된 조치 후 **다른 이름**의 windows-after.json을 수집하고 해시를 별도 보관한다. 동일 자산·규칙 버전·범위·검증 채널·시각 관계를 기록한다. FAIL→PASS는 개선 관찰이며 조치 이력이 없으면 조치 수행을 확정하지 않는다.

## 보고서/증적 인덱스/비교 연동

`to_report_snapshot(report, snapshot_id=...)`가 기존 ReportResult/SourceSnapshot을 재사용한다. 자동과 합성 분석 채널을 구분하고 수동 PASS를 생성하지 않는다. `day=0`은 Day1~5 일차가 아닌 phase2 외부 소스라는 명시적 표식이다. 기존 `normalize()`와 증적 인덱스의 Day2~4 허용 경로 정책은 그대로다. 이 초기 어댑터를 기존 Day5 최종 CLI에 자동 주입하지 않는다.

후속 통합 전 필요한 작업: phase2 입력 종류/day 의미의 정식 확장, 비공개 증적 디렉터리 allowlist·원본 파일 바인딩을 갖춘 인덱스 정책, 수집 원본 해시와 독립 기대 해시 연결, 비교 시 source/scope/verification_method/버전/시각/역할 일치 검사, PDF 템플릿 검토. 현재 digest URI만으로 기존 인덱스가 로컬 파일을 찾았거나 무결성을 검증했다고 주장하지 않는다. 별도 원본 수집 해시 확인과 인덱싱은 구분한다.

## 오류 대응과 실습 완료 조건

- 권한 부족/명령 없음: 해당 도구의 권한·모듈·64비트·OS 역할을 VM에서 확인한다. 자동 권한 확대나 오류를 PASS로 치환하지 않는다.
- 버전/역할 미확인: Edition/Caption/BuildNumber와 DomainRole을 확인하고 원본 JSON을 임의 수정하여 결과를 강제하지 않는다. 지원 후보 밖은 별도 검토한다.
- 해시 불일치: 분석을 중단하고 원본과 전달 이력을 조사한다. 현재 파일 해시로 기대값을 덮어써 VERIFIED를 만들지 않는다.
- 감사 NEEDS_REVIEW, 인쇄 역할 미승인, 도메인 암호 유효 정책 미확인은 현재 설계상의 확인 한계다. 추가 검증 없이는 PASS로 전환하지 않는다.
- 실제 수집 JSON/화면/원본 정책/해시 목록은 비공개 보관하고 Git stage/commit에 포함하지 않는다. 암호·인증 토큰·키를 수집 인수나 승인 ID로 전달하지 않는다.

초기 구현 완료는 합성 단위 테스트·전체 회귀 결과 확인, 안전한 기본 실행, PowerShell 구문 검사, 이 준비 문서 작성까지다. 실제 실습 완료는 승인된 Server VM의 버전/역할/권한을 확인하고 원본 해시·시각·자산 연결을 보존한 수집본, 각 판정의 수동 대조, 감사·도메인 등 미확인 항목의 별도 기록, 승인된 경우의 조치·재점검과 복구 확인이 있어야 한다. 모든 항목 PASS를 실습 종료 조건으로 강제하지 않는다.

## v0.3 암호 기준·감사 의미 분석·Windows 전용 보고서

### 실제 입력 확인 결과와 재수집 필요성

이번 입력은 **logs/phase2-windows/windows-followup-v02.json → windows-password-after-v02.json**이다. 과거 시간 오류가 있던 windows-before.json을 정상 baseline으로 재사용하지 않았다. 두 새 파일은 동일 자산, Server 2022 / 10.0.20348 / build 20348 / 독립 서버이며 수집 시각은 다음 순서다.

| 자료 | 원본 수집 시각 | 해시 대조 상태 |
|---|---|---|
| windows-followup-v02.json | 2026-11-06T07:47:26.3690846+00:00 | 측정 SHA-256 9ff97bcfd45c41a38271995964c7c2e093855742f8979e7fc4a61aba3f1eafaa. 이번 요청에 독립 기대값이 없어 NOT_VERIFIED |
| windows-password-after-v02.json | 2026-11-06T07:55:02.3750883+00:00 | 제공된 기대 SHA-256 9fe80c5bfea2eea8fbe49d950a453e77b5687bbf9742f8bef34ce6e44245953b와 일치 |

**두 JSON의 security_policy.values에는 merged_policy=true만 있으며, 길이·복잡성·잠금 임계/기간/초기화 수치가 없다.** 감사도 parser_verified=false만 있고 하위 범주 값은 없다. 따라서 사용자 실습 설명의 0→14, 1→1, 0→10을 JSON에 입증된 관찰로 옮기지 않는다. 원본에 숫자를 삽입하지 않고 보고서에 null/NOT COLLECTED로 표시한다. 기존 수집 파서가 왜 숫자를 읽지 못했는지는 원본 INF를 보지 못해 확정하지 않았다.

새 파서는 BOM/공백/주석이 있는 [System Access]와 알려진 숫자 키를 처리하며, 전체 숫자 파싱 실패를 ERROR(parse_failed)로 기록한다. 부분 누락은 해당 점검의 NEEDS_REVIEW다. 정규화 JSON만 영구 보관하고 원본 전체 정책은 출력하지 않는다. 새 파서와 감사 API 수집은 **합성 테스트·구문/컴파일 확인 완료, 실제 VM 재수집 미완료**다.

### 내부 기준 파일과 실제 승인

`rules/windows-server-lab.json`을 기본으로 읽고 `--policy`로 명시적 별도 파일을 지정할 수 있다. 기본 파일은 **DRAFT**, 승인 주체/시각/근거/자산 목록은 미입력이다. 길이 14·복잡성 활성·임계 10은 사용자 요청에 따른 제안이고, 잠금 기간 및 초기화 기간은 **null**이다. 현재 값 30분을 승인값으로 자동 복사하지 않는다. 감사 성공/실패 요구값도 DRAFT 제안이며 공식 기준이 아니다.

관리 필드:

- policy_id/version: 내부 기준 식별자와 버전. 대상 규칙 002/003/004/009에 적용된다. 서로 같은 버전 문자열이어도 정책 파일 SHA-256이 다르면 직접 비교하지 않는다.
- approval.status/authority/approved_at/basis: DRAFT 또는 APPROVED, 승인 주체 ID, 시간대가 있는 실제 승인 시각, 설정 근거 문서 ID. 식별자는 비밀정보가 아닌 영문·숫자·기호 식별자로 입력한다. 임의 승인값을 생성하지 않는다.
- approval.scope: 명시적 asset_ids/server_releases/build_numbers/check_ids 및 standalone_local_sam_and_system_audit 범위. 도메인 사용자/GPO/FGPP를 이 기준으로 확정하지 않는다.
- approval.evidence: 실제 승인 자료의 경로와 독립 기대 해시. 자료는 프로젝트 내부 **evidence/phase2-windows/approvals/** 아래의 txt/json/pdf만 허용한다. 경로 이탈·링크/정션·숨김/비밀정보 파일을 거부한다. 자료 내용은 보고서에 복사하지 않는다.
- `--accept-policy-approval`: 운영자가 승인 문서의 주체·범위·기준 일치를 실제 검토했다는 명시적 확인. 해시가 같다는 이유만으로 승인 주체의 진위나 문서 내용을 자동 인증하지 않는다. 이 옵션만으로 DRAFT나 누락 자료를 승인할 수 없다.

승인 파일과 스위치가 모두 충족되어도 자산/빌드/역할/필수 값/증적 무결성이 미확인인 항목은 PASS가 아니다. 004는 임계값과 기간·초기화 기간이 모두 승인값과 정확히 일치해야 한다. 002는 승인된 최소 길이 이상, 003은 활성 여부를 비교한다. 승인 후 과거 저장본을 같은 기준으로 **재분석**할 수 있지만 해당 기준이 원래 수집 당시 적용됐다고 주장하지 않는다. 비교 모델의 조치 이력 확인 여부는 계속 false다.

### 감사 하위 범주 의미 분석

[Microsoft AuditQuerySystemPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy), [AUDIT_POLICY_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information), [공식 GUID 상수](https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants)를 기준으로 읽기 전용 수집을 설계했다. 언어별 CSV 헤더/표시 이름을 추정하지 않는다. 필요한 AUDIT_QUERY_SYSTEM_POLICY 접근 또는 SeSecurityPrivilege를 자동 부여하지 않는다. 실패는 ERROR다.

| 의미 | 고정 GUID |
|---|---|
| Logon | 0cce9215-69ae-11d9-bed3-505054503030 |
| Credential Validation | 0cce923f-69ae-11d9-bed3-505054503030 |
| User Account Management | 0cce9235-69ae-11d9-bed3-505054503030 |
| Audit Policy Change | 0cce922f-69ae-11d9-bed3-505054503030 |
| Process Creation | 0cce922b-69ae-11d9-bed3-505054503030 |

시스템 조회 플래그 1=성공, 2=실패, 3=둘 다, 4=명시적 감사 없음, 0=성공/실패 비트 없음으로 해석한다. 알 수 없는 값·모순 플래그·중복/알 수 없는 GUID는 파싱 오류이며, 5개 중 누락이 있으면 REVIEW다. parser_verified=true만으로 PASS를 만들지 않는다. 예전 parser_verified=false 입력도 계속 읽되 REVIEW다. 프로세스 생성의 실제 명령행이나 이벤트 기록은 수집하지 않는다. 시스템 설정 적합성은 실제 이벤트 발생·전달, 사용자별 제외 정책, 전체 감사 정책의 완전성을 증명하지 않는다.

### 오프라인 전후 비교와 JSON/PDF

`config_audit/windows_report.py`는 명시적 두 파일만 읽고 기존 evaluate 기반 결과·공통 보고서 모델·비교 엔진을 재사용한다. 새 출력 디렉터리에만 windows-report.json/pdf를 생성하며 기존 Day5 보고서를 건드리지 않는다. 보고서에는 9개 항목의 실제 저장값·상태·권고, 내부 기준/승인 상태, 원본 수집/재분석 시각, 실제/독립 기대 해시, 미검증 사유가 포함된다. 영문 PDF는 로컬 오프라인 검토용이며 KISA 인증 또는 실환경 전체 검증 완료를 주장하지 않는다.

비교는 동일 자산/제품/OS·빌드/역할/항목/범위/수집 방식/규칙/기준 파일, 정상 수집 순서와 양쪽 독립 기대 해시 일치를 확인한다. 파일이 없거나 해시가 다르면 입력 오류다. 독립 기대 해시 없음은 NOT_VERIFIED로 유지하고 최종 개선을 허용하지 않는다. 다른 자산이나 중복 후보에서 임의로 하나를 고르지 않는다. 관찰값 변화·진단 변화·엄격한 개선 판정은 별도다.

현재 실제 두 파일의 v0.3 결과는 암호 3개와 감사의 **NEEDS_REVIEW 유지**, 최종 개선 0건이다. 개선 후 파일의 전체 재분석은 PASS 4 / NEEDS_REVIEW 5 / ERROR 0이다. baseline의 독립 기대 해시가 없으므로 이번 baseline 재분석은 모든 항목 미검증이며, 이전 실행 결과를 덮어쓴 것이 아니다.

```powershell
# 기존 파일만 이용. 두 실제 파일에서 누락된 값은 끝까지 미수집으로 표시된다.
.\.venv\Scripts\python.exe -B -m scripts.run_windows_audit `
  --before-json .\logs\phase2-windows\windows-followup-v02.json `
  --input-json .\logs\phase2-windows\windows-password-after-v02.json `
  --expected-sha256 9FE80C5BFEA2EEA8FBE49D950A453E77B5687BBF9742F8BEF34CE6E44245953B `
  --output-dir <존재하지-않는-새-Windows-보고서-디렉터리>
```

baseline의 전달 전 별도 보관한 해시가 확보되면 `--before-sha256`으로 추가한다. 현재 측정한 해시를 기대값으로 재사용하지 않는다. 실제 승인 후에만 `--policy <실제-승인-기준.json> --accept-policy-approval`을 사용한다.

실제 VM 재수집은 보완된 수집 스크립트를 기존 절차대로 **새 파일명**으로 실행하고, security_policy의 5개 숫자/불리언 키와 audit의 method/5개 GUID/mask가 있는지 확인해야 한다. 설정은 변경하지 않는다. 새 원본 해시를 VM에서 따로 보관한다. 과거 숫자가 누락된 baseline을 수정하거나 새 현재 수집으로 과거의 0 값을 입증할 수는 없다. 별도 과거 원본 수집 자료가 없다면 과거 0→14/0→10 개선은 계속 미검증으로 남기고, 신규 정상 baseline부터 추후 재점검 관계를 만든다.

검증 명령:

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_windows_audit tests.test_windows_policy
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
```

단위 테스트의 승인 자료·PASS/FAIL은 임시 폴더의 명시적 합성 fixture다. 실제 승인 문서를 생성하거나 실제 서버 PASS를 위조하지 않는다. 기존 v0.1/v0.2 수집 JSON은 계속 읽지만, 암호/감사 판정의 새 승인 요구를 우회하지는 않는다.

## 개인 실습용 LAB 모드 (포트폴리오 기본 보기)

`--mode LAB`은 실제 설정값과 사용자 PowerShell 확인 기록을 내부 실습 기준으로 평가한다. 기본 CLI 모드는 기존과 동일한 STRICT이며, LAB은 명시적으로 선택한다. LAB에는 조직 승인 문서·DRAFT 해제·독립 기대 해시가 필수 조건이 아니다. 알려진 해시 불일치는 여전히 오류로 처리하며, 값이 없는 항목은 PASS로 만들지 않는다. 공통 evaluate()/AuditStatus는 그대로 재사용한다. 실제 서버 설정을 바꾸는 명령은 실행하지 않는다.

- `rules/windows-server-personal-lab.json`: LAB-1.0 개인 기준. 암호 길이 ≥14, 복잡성 활성, 잠금 임계 10·기간 30분·초기화 30분. 지정된 방화벽 프로필 활성. 감사의 5개 GUID별 성공/실패 요구를 명시한다. 공식 KISA 기준이나 고객 인증이 아니다.
- `config_audit/windows_lab.py`: 자동 JSON과 수동 확인을 별도 채널로 평가하고 LAB 결과를 만든다. 다른 자산·OS·역할을 섞지 않는다. 도메인의 유효 암호 정책을 로컬 값만으로 확정하지 않는다.
- `evidence/phase2-windows/manual-lab.json`: 사용자가 대화에서 확인한 PowerShell 설정·조치·재점검 기록을 전사했다. 원본 콘솔 파일이 첨부됐다고 표시하지 않으며 확인 시각은 null이다. 사용자 확인 출처는 `user_powershell_confirmation`이다. 이는 합성 테스트 fixture가 아니다.
- `config_audit/windows_lab_report.py`: LAB 성과를 먼저 보여주는 별도 PDF. JSON에는 자동·수동·평가에 사용한 값과 값별 출처를 모두 보존한다.

### 이번 실제 사용자 확인 기록

| 항목 | 개선 전 → 후 | LAB 판정 | 완료 표현 |
|---|---|---|---|
| Guest | 비활성 유지 | PASS | 양호 유지, 자동 JSON |
| 최소 암호 길이 | 0 → 14 | PASS | 사용자 PowerShell 확인에 따른 조치·재점검 완료 |
| 복잡성 | 1 → 1 | PASS | 양호 유지, 사용자 PowerShell 확인 |
| 잠금 | 임계 0 → 10, 개선 후 기간/초기화 30/30분 | PASS | 사용자 PowerShell 확인에 따른 조치·재점검 완료. 개선 전 기간/초기화는 미확인으로 보존 |
| Spooler | 서비스·Print 기능 미설치 + 인쇄 불필요 확인 | PASS | 서비스 노출 위험의 현재 LAB 기준 충족. 설정 변경에 의한 개선이라고 주장하지 않음 |
| 방화벽 | 지정 프로필 활성 | PASS | 양호 유지, 자동 JSON |
| SMBv1 | 비활성 | PASS | 양호 유지, 자동 JSON |
| SMB 서명 | False → True | PASS | 사용자 PowerShell 확인에 따른 조치·재점검 완료 |
| 감사 | 하위 GUID 실제 값 없음 | NEEDS_REVIEW | 5개 하위 항목 NOT_TESTED, 값 확보 후 실제 미충족 항목별 FAIL/PASS 표시 |

사용자는 이 VM에서 인쇄 기능이 불필요하다는 점을 추가로 확인했다. 기존 JSON의 `required:null`은 수정하지 않고 수동 확인의 `required:false`와 연결한다. 서비스·기능 부재는 자동 출처, 불필요 여부는 수동 출처로 표시한다. LAB의 Spooler PASS는 해당 서비스 노출 범위에 한정한다.

SMB 서명의 False→True는 더 이른 별도 수동 실습 시나리오다. 최신 JSON baseline의 실제 서명 값은 이미 True이며, 이를 False로 고치거나 그 파일에서 False가 수집됐다고 주장하지 않는다. 수동 baseline은 별도 scenario_id와 함께 표시한다. 현재 자동값과 수동값이 충돌하면 임의로 하나를 골라 PASS로 덮어쓰지 않고 충돌 항목을 표시한다.

`LAB_REMEDIATION_AND_RETEST_COMPLETE`는 사용자가 조치·순서·재점검을 확인했고 해당 수동 baseline FAIL→현재 LAB PASS인 실습 완료 표시다. 확인되지 않은 시험 시각이나 원본 파일을 생성하지 않는다. 실제 조치가 없던 유지 항목은 UNCHANGED_PASS/CURRENT_LAB_PASS로 구분한다.

### STRICT 고급 검증 보존

LAB 보고서의 `advanced_validation` 아래에 기존 STRICT 보고서 전체를 별도 보존한다. 이번 파일 쌍의 STRICT 비교는 기존과 동일하게 9건 UNVERIFIABLE이며, 이는 개인 실습의 8개 PASS/3건 완료를 덮어쓰지 않는다. STRICT 기준 파일이 잘못되거나 승인 자료가 없어서 로딩에 실패한 경우 그 오류를 고급 보기 안에 기록하고 LAB 평가를 막지 않는다. 기존 Day5 보고서·기존 STRICT 결과 파일은 수정하지 않는다.

```powershell
Set-Location C:\Projects\infrastructure-security-scanner-clone
.\.venv\Scripts\python.exe -B -m scripts.run_windows_audit --mode LAB `
  --before-json .\logs\phase2-windows\windows-followup-v02.json `
  --input-json .\logs\phase2-windows\windows-password-after-v02.json `
  --lab-manual .\evidence\phase2-windows\manual-lab.json `
  --output-dir <존재하지-않는-새-LAB-보고서-폴더>

# 현재 파일 한 개에 대한 LAB 평가. 자동/수동 채널과 STRICT 분석을 함께 출력한다.
.\.venv\Scripts\python.exe -B -m scripts.run_windows_audit --mode LAB `
  --input-json .\logs\phase2-windows\windows-password-after-v02.json `
  --lab-manual .\evidence\phase2-windows\manual-lab.json

.\.venv\Scripts\python.exe -B -m unittest tests.test_windows_lab tests.test_windows_audit tests.test_windows_policy
```

LAB 결과는 PASS 8 / NEEDS_REVIEW 1, 조치·재점검 완료 3건이다. 감사 항목만 GUID 기반 실제 값을 추가로 확인해야 한다. 기존 수동 암호·서명 확인을 인정받기 위한 승인 서류나 과거 JSON 수정은 필요하지 않다. 알려진 독립 해시는 선택적으로 `--expected-sha256`/`--before-sha256`에 전달할 수 있다. 이 해시 대조도 수집 출처의 진위 인증은 아니다.
