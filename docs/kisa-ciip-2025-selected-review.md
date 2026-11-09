# KISA 주요정보통신기반시설 상세가이드 — 선택 항목 재판정

**출처:** 한국인터넷진흥원 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」, **게시일 2025-12-24**. PDF 표지에는 **2026**으로 표시됨.

- 공식 배포: https://www.kisa.or.kr/2060204/form?lang_type=KO&postSeq=22
- 이 프로젝트는 KISA 전체 항목의 자동진단·인증 적합성을 주장하지 않음
- KISA 권고는 참고 기준이며, 실제 최종 판정에는 기관 정책, 운영 환경, 예외 및 보완통제 검토가 필요

## 설계 결정

기존 `LINUX-LAB-*`, `WIN-LAB-*` 기준과 역사적 개선 증적은 **그대로 둔다**. 서로 다른 기준을 같은 결과의 PASS로 덮어쓰면 과거 실습의 의미가 변하기 때문이다. 별도 읽기 전용 재판정(`config_audit/kisa_ciip_review.py`)은 **저장된 LAB 보고서의 관찰값**을 KISA 권고 기준과 비교한다. VM/Docker/AWS를 실행하거나, 설정을 수정하거나, 누락된 관찰값을 생성하지 않는다.

## 확인된 기준과 실제 프로젝트 결과

| KISA 항목 | 가이드의 일반 권고 | 기존 LAB 점검 | 역사적 LAB 상태 | KISA 비교 결과(기록값 기준) |
|---|---|---|---|---|
| U-18 `/etc/shadow` | root 소유, 권한 `0400` 이하 | `LINUX-LAB-003`: root 소유, `0640` | LAB PASS | **FAIL** — `0640`은 KISA 권고와 다름 |
| W-04 계정 잠금 임계값 | 5회 이하, 계정 잠금 활성화 | `WIN-LAB-004`: 10회 | LAB PASS | **FAIL** — 10회 > 5회 |
| W-08 계정 잠금 기간 | 잠금 지속·잠금횟수 초기화 **각각 60분 이상** | `WIN-LAB-004`: 각 30분 | LAB PASS | **FAIL** — 각 30분 < 60분 |

**주의:** 위 결과는 Git에 기록된 LAB 문서의 설정값을 KISA 기준과 비교한 예상 재판정이다. 자동 실행에 사용되는 LAB 원시 보고서가 공개 저장소에 모두 있는 것은 아니다. 실제 원시 파일 재입력·독립 검증이 완료되었다는 뜻이 아니다. Windows의 이전/이후 수치는 일부 **PowerShell 수동 확인** 기록이며 자동 수집 데이터로 변환하지 않는다.

U-18은 정수의 단순 `mode <= 0o400` 비교 대신 비트 마스크로 평가한다. 예를 들어 `0044`는 수치상 `0400`보다 작지만 그룹·기타 사용자 읽기 권한이 있으므로 FAIL이다. 파일 소유자·일반 파일 여부·심볼릭 링크 여부도 함께 확인한다.

W-04는 `0`이 계정 잠금 미사용을 뜻할 수 있으므로 0~5가 아닌 **1~5**를 PASS로 평가한다. W-08은 `lockout_duration`, `reset_minutes`의 각 값을 독립적으로 확인한다.

## 사용법 — 읽기 전용, 저장된 보고서만

프로젝트 루트의 PowerShell에서:

```powershell
.\.venv\Scripts\python.exe -m scripts.compare_kisa_ciip `
  --linux-report <기존_Linux_MySQL_LAB_보고서.json> `
  --windows-report <기존_Windows_LAB_보고서.json>
```

선택한 하나의 보고서만 `--linux-report` 또는 `--windows-report`로 입력할 수도 있다. 실행 결과는 표준 출력에 JSON으로 표시되고 기존 보고서나 장비 설정은 수정하지 않는다.

예: `LINUX-LAB-003` 원본이 PASS라도 KISA U-18 비교 결과는 FAIL일 수 있다. 출력에 원본 `original_lab_status`와 `kisa_recommendation_result`를 함께 남겨 기준을 구분한다.

- 출력의 `input_sha256`은 **입력 파일 바이트 해시**이며 출처 진위 또는 실제 운영 상태 증명이 아니다.
- 수집 미실시·오류·부적용 상태는 재판정에서 PASS로 바뀌지 않는다.
- 원본이 합성 데이터이면 결과도 합성 데이터 비교일 뿐이다.
- 이 비교는 **U-18, W-04, W-08 세 항목만** 다루며 KISA 정합성 전수 검증이 아니다.

## 추가 보완 검토(이번 작업에서 변경하지 않음)

1. Windows **W-09 비밀번호 관리정책**은 비밀번호 복잡성, 길이, 사용 기간 등 모든 해당 조건과 적용 정책(로컬/도메인)을 확인하기 전에는 전체 PASS로 판정할 수 없다.
2. Linux SSH 설정은 `sshd -T` 점검이 유용하지만 Match 블록, 실제 원격 연결, 대체 관리자 접근 통제는 별도 검증이 필요하다.
3. MySQL `require_secure_transport=ON`은 TCP TLS 핸드셰이크·인증서 검증을 입증하지 않는다.
4. Router/Switch 가상 Linux LAB는 물리 장비 진단·VLAN 관리 CLI를 대체하지 않는다.
5. 기타 KISA 항목은 **공식 항목 코드·판정 조건·제품 버전·증적 채널**을 검토한 후 개별 추가해야 한다. 근거가 없으면 KISA 준수라고 표기하지 않는다.

## 검증

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_kisa_ciip_review -v
```

테스트에서는 위 과거 값이 KISA 권고 기준에 FAIL인 점, 권고값 PASS, 미수집/오류 처리, 심볼릭 링크·파일 권한, 계정잠금 비활성 상태와 일부 값 누락을 확인한다. **테스트가 통과해도 실제 LAB 재점검 성공을 의미하지 않는다.**


## 실제 KISA 권고값에 맞춘 LAB 재조치 및 PASS 확보 절차

**이번 분기에서 변경한 것은 KISA 비교 모듈뿐 아니라 별도 실습 환경의 개선값이다.** 다만 GitHub의 코드 변경 자체는 새 VM 실측 PASS가 아니다.

### Linux U-18: 실제 Docker Replay LAB 재생성 후 측정

기존 `before` 단계의 취약 설정은 그대로 두고, `after` 단계의 `/etc/shadow` 권한을 `0400`으로 변경했다. `LINUX-LAB-003` 내부 판정도 `0400`을 허용한다. 이전에 저장한 `0640` 개선 기록은 과거 LAB PASS로 보존하지만 KISA U-18에서는 여전히 FAIL이다.

**프로젝트 루트 Windows PowerShell**에서 먼저 현재 replay 실습과 원본 증적 보존 상태를 확인한 뒤, 격리 replay Linux 컨테이너만 재생성한다.

```powershell
$env:LINUX_MYSQL_STAGE = 'after'
docker compose -f .\lab\linux-mysql-retest\compose.replay.json build linux
docker compose -f .\lab\linux-mysql-retest\compose.replay.json up -d --no-deps --no-build --force-recreate --wait --wait-timeout 60 linux

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force .\logs\phase2-linux-mysql-replay | Out-Null
$report = ".\logs\phase2-linux-mysql-replay\after-kisa-$stamp.json"
.\.venv\Scripts\python.exe -B -m scripts.run_linux_mysql_audit --execute --lab-profile replay --output $report
.\.venv\Scripts\python.exe -B -m scripts.compare_kisa_ciip --linux-report $report
```

이 과정은 기존 replay Linux 컨테이너를 재생성하므로 현재 그 컨테이너에 보존해야 하는 상태가 있다면 먼저 백업한다. 기존 `scanner-p2lm` 프로젝트의 컨테이너는 대상으로 하지 않는다. **KISA U-18 PASS는 마지막 비교 출력에 실제 재수집값 `0400`과 원본 출처가 존재할 때만 확정한다.**

### Windows W-04/W-08: standalone Windows Server VM에서 실제 정책 변경·재수집

`rules/windows-server-kisa-2025-lab.json`은 KISA 권고값인 잠금 임계값 **5회**, 잠금 지속·초기화 기간 **각각 60분**을 별도 LAB 기준으로 정의한다. 기존 `windows-server-personal-lab.json`의 10/30/30 기준과 과거 기록은 보존한다.

Windows Server **2022 격리 가상머신의 관리자 PowerShell 콘솔**에서만 실행한다. 대상 컴퓨터 이름 확인, 도메인 비가입, 독립 서버, 가상화 모델, 관리자 권한 확인이 통과해야 변경할 수 있다.

```powershell
# VM 안에서 실행: 미리 C:\LabEvidence 디렉터리를 준비
.\scripts\apply_windows_kisa_lab.ps1 `
  -ExpectedComputerName $env:COMPUTERNAME `
  -OutputPath 'C:\LabEvidence\windows-kisa-after.json' `
  -Apply -AcknowledgeIsolatedLab
```

이 스크립트는 현재 VM에서 `secedit /export`로 잠금 정책을 수집하고, 명시적 `-Apply`가 있을 때만 로컬 잠금 정책을 변경한 뒤 다시 수집한다. 출력 파일이 이미 있으면 중단한다. **도메인/GPO 환경이나 실서버에 적용하면 안 된다.**

수집한 JSON을 프로젝트 작업 PC로 **비공개** 복사한 다음 다음을 실행한다.

```powershell
.\.venv\Scripts\python.exe -B -m scripts.compare_kisa_ciip `
  --windows-report '.\evidence\windows-kisa-after.json'
```

여기서 W-04·W-08이 모두 PASS여야 이 **VM의 확인된 로컬 정책 두 항목**에 대해 KISA 권고를 만족했다고 표현할 수 있다. 전체 Windows 정책이나 KISA 전수진단 PASS가 아니다.

기존 Windows LAB 리포트를 별도의 KISA 임계값으로 확인할 때는 `scripts.run_windows_audit --mode LAB --lab-criteria .\rules\windows-server-kisa-2025-lab.json`을 이용한다. 실행에 필요한 `--input-json`, `--before-json`, `--output-dir` 등은 기존 사용법을 따라 제공한다. 과거 10/30/30 수치를 넣으면 FAIL이 정상이다.

### PASS 판정 원칙

- **새로운 관찰값을 재수집하고 KISA 판정에 입력한 경우에만** 새 PASS로 보고
- Linux U-18, Windows W-04/W-08 이외 항목의 공식 가이드 전수 매핑·적용성 판단은 **아직 미완료**
- 기존 개인 LAB의 5+9+8+8개 등 상태를 모아서 전체 KISA 준수율이라고 표기하지 않음
- 단위 테스트용 PASS는 실제 VM 또는 Docker 재점검의 PASS를 대신하지 않음


## 자동 실행된 새 격리 LAB 실측 증적 (2026-11-09)

**이 절은 문서상의 예상 결과가 아니라, GitHub Actions에서 일회용 격리 환경을 실제로 구성·변경·재수집한 결과이다.** 이는 3개 항목의 실습 재현으로 범위를 제한한다.

| 공식 항목 | 실제 신규 실행 환경 | 조치·재점검 결과 | 출처 |
|---|---|---|---|
| U-18 | GitHub Actions Linux 격리 Docker Replay LAB | `/etc/shadow` `0400` 수집, KISA 비교 **PASS**. Linux/MySQL 기존 LAB 10개는 새로 실행해 FAIL 10→PASS 10 | [실측 워크플로](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/42574765798) |
| W-04 | GitHub Actions 일회용 Windows Server 2022 standalone VM | 로컬 정책 잠금 임계값 5회 적용→`secedit` 재수집→KISA 비교 **PASS** | [Windows 실측 워크플로](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/42575461694) |
| W-08 | 같은 Windows Server 2022 VM | 잠금 기간·초기화 각 60분 적용→`secedit` 재수집→KISA 비교 **PASS** | 동일 실행 |

- GitHub Actions의 기존 CI 성공은 **프로그램 테스트**, 상기 실습 워크플로 성공은 **격리 환경 실측**에 해당한다. 서로 구분한다.
- Windows의 최초 측정값과 개선 후 측정값은 Actions의 `windows-kisa-after.json` 아티팩트에 보존된다(보존 기간 7일).
- Linux의 `before.json`, `after.json`, `kisa-u18.json`은 별도 Actions 아티팩트로 보존된다(보존 기간 7일).
- Windows 2022 CI VM의 PASS를 사용자의 기존 Hyper-V VM에서 PASS로 측정한 것처럼 설명하면 안 된다.
- U-18, W-04, W-08 **세 항목만 신규로 KISA 권고값을 충족했다고 실측 확인**했다. Linux/MySQL 10개는 **내부 LAB 기준**의 PASS이며 KISA 공식 항목 10개 PASS라는 뜻이 아니다.
- 기존 저장 자료에서 `0640`, `10회`, `30분`이 KISA 권고 기준에 미달한다는 사실은 그대로 유지한다. 새 실습 결과로 과거 기록을 덮어쓰지 않는다.
- **전체 KISA 상세가이드 전수 PASS 또는 프로젝트 전체 KISA 준수를 주장하지 않는다.** 보안장비, 네트워크, WEB/WAS, AWS 및 Windows의 추가 항목은 개별 공식 기준 적용성·실제 재점검이 필요하다.
