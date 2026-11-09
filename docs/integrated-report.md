# 오프라인 통합 JSON/PDF 보고서

> 역사적 Day5 구현·산출물 설명이다. 현재 Phase2 성과와 테스트의 기준은
> [포트폴리오 근거 매핑](audit-evidence-mapping.md)이다. 아래 Day3 입력과
> 기존 25레코드 보고서에는 역사적 IDS 채널도 포함돼 있지만, Suricata IDS/IPS는
> 현재 최종 검증 성과·개선 집계에서 제외한다. 원본 JSON/PDF를 수정하거나
> Phase2 자료를 넣어 당시 산출물을 재작성하지 않는다. 과거 테스트 수치는 해당 단계 기록이다.

## 실행

프로젝트 루트의 Windows PowerShell에서 실행한다.

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_integrated_report
```

기본 출력은 `reports/day5/`이며 명시적으로 다른 `reports/` 하위 디렉터리를
선택할 수 있다. `--project-root`로 프로젝트를 지정할 수 있으나 출력은 그
프로젝트의 `reports/` 내부로 제한한다. 링크를 통한 출력 이탈도 거부한다.
VM, Docker, SSH, API, DB, 외부 명령어를 실행하지 않는다. 기존 DB 기반
`generate_report()` / `build_integrated_snapshot()`를 호출하지 않는다.

입력이 모두 읽혔으면 `COMPLETE_WITH_LIMITATIONS`와 종료 코드 0을 반환한다.
이는 보안 진단 전체 PASS가 아니다. 입력 누락·파싱 오류는 부분 보고서의
입력 ERROR로 표시하며 `PARTIAL`, 종료 코드 2를 반환한다. 생성 실패나
잘못된 인자는 종료 코드 1과 고정 오류 메시지를 반환한다. 원문 예외나
인자 값은 오류 출력에 포함하지 않는다.

## 모듈 구성

- `config_audit.final_report`: 명시된 로컬 입력의 안전한 읽기, 공통 모델,
  증적 인덱스, 전후 비교, 설명 근거와 집계를 한 번 구성한다.
- `api.integrated_report_pdf`: 별도 Day5 스키마의 A4 한글 PDF 렌더러.
- `api.report_pdf.render_day5_report_pdf`: 새 렌더러로의 얇은 진입점이다.
  기존 `render_report_pdf`는 그대로 유지한다. 기존 한글 폰트 등록, 색상,
  텍스트 이스케이프와 ReportLab 표 스타일을 재사용한다.
- `scripts.run_integrated_report`: 오프라인 생성 전용 CLI.

기존 `reporting.py`, `evidence_index.py`, `comparison.py`를 재사용한다.
컬렉터와 평가 엔진을 실행하거나 원래 판정을 다시 계산하지 않는다.

## 동일 통합 스냅샷과 산출물

| 파일 | 내용 |
|---|---|
| day5-integrated-report.json | 원본 공통 모델, 증적 인덱스, 비교, 시점별 집계, 세부 설명·근거, 검증 한계 |
| day5-integrated-report.pdf | 같은 스냅샷의 표지·목차·진단 개요·요약·세부 결과·증적·재점검·후속 조치 |
| day5-evidence-index.json | 같은 보고서 ID·내용 해시와 내장 인덱스의 동일한 복사본 |
| day5-comparison.json | 같은 보고서 ID·내용 해시와 내장 비교 결과의 동일한 복사본 |
| day5-manifest.json | 보고서 ID·내용 해시, 각 산출물의 실제 파일 해시·크기, 입력 ID·해시, 시각·실행 상태·한계 |

JSON과 PDF를 별도로 재수집하지 않는다. 생성된 `report_id`와
`content_sha256`을 PDF에도 표시한다. PDF 메타데이터의 레코드 수는 통합
스냅샷과 동일하다. 증적·비교 JSON은 새 실행 결과가 아니라 이 스냅샷의
해당 부분을 내보낸 것이다.

`content_sha256`은 자기 필드 하나만 제외한 전체 정규 UTF-8 JSON의
SHA-256이다. 생성 시각도 내용에 포함하므로 다른 실행은 해시가 달라질
수 있다. 이 값은 실제 JSON 파일의 들여쓰기·줄바꿈을 포함한 바이트 해시와
다르다. Manifest의 `file_sha256`은 실제 파일 바이트의 해시다.
Manifest는 자기 자신을 해시 목록에 포함하지 않으므로 재귀 참조가 없다.
Manifest와 해시는 전자서명이나 증적 진위의 증명이 아니다.

보고서 전체를 임시 디렉터리에 생성한 뒤 완성된 파일을 교체하고 manifest를
마지막에 게시한다. PDF 생성 실패 시 임시 JSON을 게시하지 않는다. 파일별
교체 도중 프로세스가 중단될 수 있으므로 여러 파일에 대한 원자적 교체를
보장한다고 주장하지 않는다. 사용 전 manifest 해시를 확인해야 한다.

```powershell
Get-FileHash -Algorithm SHA256 .\reports\day5\day5-integrated-report.pdf
```

입력 JSON을 읽을 때 계산한 해시는 `observed_file_sha256`으로 기록한다.
이를 독립 기대 해시로 재사용하지 않는다. 입력 변환 직후 인덱스에서 다시
읽은 입력 파일의 해시가 달라지면 생성을 중단한다.

## 원본 보존과 설명 근거

입력은 Day2 before/after, Day3 final, Day4 manual JSON 네 개다.
Day3 로컬 아티팩트 세 개와 Day4 PF·로그 보조 자료 다섯 개를 명시적으로
인덱스에 연결한다. 디렉터리 전체를 탐색하거나 외부 참조를 비슷한 로컬
파일로 바꾸지 않는다. 실제 값이 기존 보고값과 다르면
`index_reference_difference`에 차이를 기록하고 실제 재계산 값을 사용한다.

기준·항목명·권고가 저장 결과에 없는 경우 기존 Day2/3/4 스크립트의
문자열 규칙 정의만 AST로 읽는다. 스크립트를 import/실행하거나 조건 함수를
평가하지 않는다. 근거 파일·행 번호·실제 소스 SHA-256을 기록한다.
명시적으로 일치하는 버전 1의 기준·권고만 보충한다. 버전이 없는 수동
기록에는 기존 규칙을 참고 설명으로만 표시하고 원래 검사 기준으로
확정하지 않는다. 정의를 확인할 수 없으면 자료 미제공으로 남긴다.

실제 관찰값이 저장되어 있지 않은 항목은 미저장이라고 표시한다. 운영자
시험 기록은 수동 채널에서만 보존한다. CVE/CVSS·취약 원인·위험도·조치
이력은 만들어 내지 않는다. PASS 항목을 확인된 취약점이라고 표현하지 않는다.
원시 설정, 실제 로그 본문, 인증 헤더 및 개인키를 보고서에 복사하지 않는다.
허용 필드 변환과 자격증명 표시 패턴 마스킹을 함께 적용한다. 자유 텍스트에
숨은 모든 비밀값을 자동 식별할 수는 없으므로 외부 배포 전 검토가 필요하다.

## 실제 로컬 자료의 집계

자산 5개, 고유 자산·항목 21개, 서로 다른 시점의 저장 레코드 25개다.

| 스냅샷 / 채널 | PASS | FAIL | NEEDS_REVIEW |
|---|---:|---:|---:|
| Day2 before / 자동 | 2 | 2 | 0 |
| Day2 after / 자동 | 4 | 0 | 0 |
| Day3 final / 자동 | 12 | 0 | 0 |
| Day4 manual / 수동 | 3 | 0 | 2 |

이 입력의 ERROR, NOT_TESTED, NOT_APPLICABLE 저장 판정은 각 0건이다.
Day4 자동 결과 자체는 없으므로 0건 집계를 성공으로 해석하지 않는다.
FW-01 자동 PASS 이력을 생성하지 않았으며 수동 기록을 자동 PASS로 바꾸지
않는다. Day2 after·Day3 final·Day4 manual을 명시적으로 선택한 표시에서는
자동 PASS 16건과 수동 PASS 3건/NEEDS_REVIEW 2건을 분리한다. 서로 다른
시점의 기록이며 현재 전체 안전성에 대한 종합 판정이 아니다.

증적은 고유 로컬 파일 23개, 연결 60건이며 VERIFIED 15, NOT_VERIFIED 33,
EXTERNAL_REFERENCE 12, MISMATCH/MISSING/INVALID_REFERENCE 각 0이다.
NOT_VERIFIED를 VERIFIED로 승격하지 않는다.

Day2 원본 변화는 FAIL→PASS 2건, PASS→PASS 2건이다. 범위·수집기·검증
방식이 부족하므로 엄격한 최종 비교는 UNVERIFIABLE 4건이고 개선 완료는
확정하지 않는다. Day3/4의 전후 관계는 만들지 않는다. FW-04/05 수동
NEEDS_REVIEW와 FW-06 수동 PASS를 유지하며 전체 유효 규칙집합과 규칙
세대 연속성, 누락된 Day4 자동 결과는 후속 검증 대상으로 기록한다.

## PDF 품질과 테스트

맑은 고딕 등 설치된 한글 폰트, A4 세로, 네이비·블루 디자인, 동적 목차,
페이지 번호, 상태별 색상, CJK 줄바꿈과 반복 헤더 LongTable을 사용한다.
긴 경로·해시·사유는 생략하지 않고 줄바꿈·페이지 분할한다.
실제 생성 PDF는 25페이지다. 실행 시 자료에 따라 페이지 수는 달라질 수 있다.

생성기가 반환하는 `pdf.visual_validation=NOT_PERFORMED_BY_RENDERER`는
시각 검토를 수행했다는 주장을 방지한다. 실제 Poppler 렌더링 후 별도 QA를
수행했다면 해당 PDF의 바이트 해시·시각·검토 범위와 결과를 manifest의
`visual_review`에 별도로 기록할 수 있다. 새로 생성하면 기존 검토는
유효하다고 재사용하지 않으므로 다시 렌더링·검토해야 한다.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-reporting-test.txt
.\.venv\Scripts\python.exe -B -m unittest tests.test_integrated_report
.\.venv\Scripts\python.exe -B -m unittest tests.test_offline_reporting tests.test_evidence_integrity tests.test_remediation_comparison tests.test_integrated_report
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py'
```

실제 생성에는 기존 requirements.txt의 ReportLab을 사용한다. pypdf는
텍스트 추출·폰트 임베딩·페이지·내용 검사용 테스트 의존성이다. 이번 실행은
번들 pypdf 6.10.0을 Windows 가상환경에 오프라인으로 추가했다.
기존 Bash 환경 실패는 독립적으로 기록하며 성공 처리하거나 건너뛰지 않는다.
이번 실행은 신규 테스트 27개와 Day5 전체 140개가 통과했다. 전체 회귀
683개 중 682개가 통과했으며 기존 `test_ec2_owner_deployment_script_syntax`
한 개가 Git Bash `NtCreateDirectoryObject` 접근 거부(0xC0000022)로 실패했다.

## 6단계 commit·push 전 확인

소스·테스트·문서와 테스트 의존성만 우선 검토한다. 기존 미커밋 Day5 2~4단계
파일도 함께 리뷰해야 한다. `reports/`는 Git에서 제외되어 있으며 산출물을
무조건 stage하지 않는다. 실제 증적·내부 주소·민감정보의 공유 범위를
검토하고 manifest 해시, PDF 시각 검토와 미검증 상태 보존을 확인한다.
기존 Bash 실패와 Day4 자동 자료 부재는 완료된 검증으로 표현하지 않는다.
이번 단계에서는 commit 및 push를 수행하지 않는다.

## 저장 결과 정규화 모듈의 입력·안전 계약

다음은 별도 보고서 생성보다 앞선 `config_audit.reporting`의 읽기 전용 변환 계약을 설명한다. 본 절은 과거 구현 기록이며 현재 PDF·증적 인덱스·비교 기능이 없다는 의미는 아니다. 현행 모듈은 Collector, `evaluate()`, DB 및 외부 명령을 자동 실행하지 않는다.

### 입력과 사용 방법

프로젝트 루트의 Windows PowerShell에서 가상환경 Python을 사용한다.
다음은 모듈 사용 예이며 새 진단이나 실장비 접속을 실행하지 않는다.

```powershell
@'
from config_audit.reporting import load_snapshot, integrate

sources = [
    load_snapshot("logs/day2-before.json", day=2, snapshot_id="day2-before"),
    load_snapshot("logs/day2-after.json", day=2, snapshot_id="day2-after"),
    load_snapshot("logs/day3-final.json", day=3, snapshot_id="day3-final"),
    load_snapshot("evidence/day4/manual.json", day=4,
                  snapshot_id="day4-manual", input_kind="manual"),
]
report = integrate(sources, evidence_sources=[
    {"path": "evidence/day4/fw04-active-rules.txt", "kind": "pf_rules_snapshot"},
    {"path": "evidence/day4/fw04-active-rules-detail.txt", "kind": "pf_rules_detail"},
    {"path": "evidence/day4/fw05-wan-tcp22.json", "kind": "raw_firewall_log"},
    {"path": "evidence/day4/fw05-wan-tcp22-retest.json", "kind": "raw_firewall_log"},
])
for source in report.snapshots:
    print(source.snapshot_id, source.import_status, len(source.results), source.diagnostics)
'@ | .\.venv\Scripts\python.exe -B -
```

`load_snapshot()`는 명시한 파일 하나만 최대 4 MiB까지 읽는다. Day2는
`ubuntu/mysql.checks`, Day3/4 자동 실행 결과는 `results` 배열을 입력받는다.
Day4 원본 수동 문서는 `input_kind="manual"`로 구분한다.
기존에 저장된 Day4 실행 결과가 별도로 있다면 명시적으로 입력할 수 있다.
수동 JSON, PF 텍스트, 원시 로그를 자동 실행 결과로 간주하지 않는다.
`normalize()`는 이미 디코딩된 문서를 입력받는 동일한 변환 함수다.

### 공통 모델

- `OfflineReport`: 스키마 버전, `generated_at`, `reanalysis_at=null`, 스냅샷,
  선택적 원본 증적 식별자, 전역 한계. 생성 시각은 새 시험 시각이 아니다.
- `SourceSnapshot`: 출처 경로, 일차, 호출자가 부여한 고유 `snapshot_id`,
  입력 종류, 변환 상태, 오류·누락 진단 및 수집 메타데이터.
- `ReportResult`: `asset_id`, `check_id`, `rule_version`, 독립적인
  `automatic`, `manual`, `analyses` 채널 및 명시된 위험도·조치 방안.
- 자동 채널: 원래의 상태, 사유, 실행 ID, `checked_at`, 범위, 증적 참조,
  API별 수집 상태·HTTP 코드·실패 단계. 수집 성공은 진단 PASS가 아니다.
- 추가 분석 채널: 저장된 `pf_snapshot`, `log_rule_evidence`의 상태·버전·시각·
  범위·한계와 별도의 로그 수집/규칙 매핑 메타데이터.
- 수동 채널: 저장된 상태와 검증 정보만 보존한다. 원본 수동 문서는
  `reported_status`를 운영자 주장으로 표시하고 이번 변환에서 재검증하지 않는다.
  원본에 없는 `VALID`, `attached=true`, 규칙 버전을 만들지 않는다.
- 증적 참조: 원래 식별자, 상대 경로 기준, 선언된 SHA-256, 종류 및
  `verification=NOT_VERIFIED`. 기존 저장 결과의 `attached`/무결성 주장이
  있어도 이번 변환에서 참조 파일을 검증했다는 의미가 아니다.

원래 시각 문자열과 오프셋을 유지한다. 시간대 없는 시각은 UTC로 변환하지
않으며 `time_basis=artifact_review`는 시험 시각과 구분한다. 원본에 수집
시각이 없으면 `checked_at`이나 파일 수정 시각으로 대체하지 않는다.
상태를 합산하여 새로운 종합 PASS/FAIL을 산출하지 않는다.

### 실제 입력의 범위와 누락

현재 로컬 저장 결과는 Day2 before 4건(FAIL 2건), after 4건(PASS 4건),
Day3 12건이다. Day3 증적 참조는 컨테이너/출력 식별자로 유지하며 실제
파일이 존재하거나 해시가 일치한다고 주장하지 않는다.

Day4 원본 `manual.json`에는 FW-02/03/06 수동 PASS와 FW-04/05 수동
NEEDS_REVIEW가 있다. 이 5건은 자동 결과가 없으므로 `automatic=null`이며
FW-01 자동 PASS를 포함한 새 자동 결과를 생성하지 않는다.
완전한 Day4 자동 실행 결과 JSON 및 저장된 PF/로그 분석 결과 JSON이
입력되지 않았다는 누락 사유를 스냅샷에 기록한다. 원본 PF/로그의 경로는
선택적으로 별도 참조할 수 있으나 분석을 다시 실행하지 않는다.

FW-04/05의 검토 필요 상태와 FW-06의 수동 PASS를 유지한다.
실제 장비를 다시 검증했다거나 전체 방화벽 정책이 안전하다고 주장하지 않는다.

Day2/3 `logs/`는 Git에서 제외된 로컬 입력이다. 다른 체크아웃에 없을 경우
`input_missing`을 기록하며 임의로 복원하거나 진단을 실행하지 않는다.

### 검증 및 안전성

필수 필드, 지원 상태, 타임스탬프 형식, 잘못된 JSON, 중복 JSON 키,
비유한 숫자, 크기 제한을 검사한다. 동일 스냅샷의
`(asset_id, check_id, rule_version)` 중복과 스냅샷 ID 중복은 거부한다.
서로 다른 스냅샷의 동일 항목은 각각 유지하며 전후 비교는 하지 않는다.
파일 변환은 원자적으로 처리하여 오류가 있으면 해당 스냅샷 결과를 비우고
`import_status=ERROR`와 고정 오류 코드를 반환한다. 이 상태는 진단 ERROR를
만들었다는 의미가 아니다. 다른 정상 스냅샷의 변환 결과는 유지할 수 있다.

원시 설정 값, 로그 본문, HTTP 헤더 및 알 수 없는 필드는 출력하지 않는다.
허용한 메타데이터에도 자격증명 표시·개인키·인증 문자열 패턴이 있으면
고정 코드로 거부한다. 오류에 입력 본문이나 OS 예외를 포함하지 않는다.
명시적 사유·범위 등 자유 텍스트는 모든 형태의 비밀값을 자동 탐지할 수
없으므로 외부 배포 전 검토가 필요하다. 위험도나 조치 방안은 입력에
명시된 경우만 보존하며 상태나 규칙명에서 추론하지 않는다.

### 테스트

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_offline_reporting
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py'
```

모의 데이터 계약 테스트와 실제 로컬 JSON의 읽기 전용 변환 테스트를 포함한다.
Git에서 제외된 Day2/3 입력이 없는 다른 체크아웃에서는 해당 로컬 통합
테스트만 입력 부재로 표시되며 모의 데이터 테스트는 계속 실행된다.
기존 Bash 문법 검사 실패는 별도 환경 문제로 기록하며 성공 처리하지 않는다.
