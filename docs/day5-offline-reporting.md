# Day5 2단계: 저장 결과의 오프라인 통합

`config_audit.reporting`은 저장된 결과를 변환하는 Python 모듈이다.
Collector, `evaluate()`, DB, 외부 명령어를 호출하지 않는다. 최종 출력 CLI,
PDF, 증적 인덱스 및 조치 전후 비교는 이번 단계의 범위에 포함하지 않는다.

## 입력과 사용 방법

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

## 공통 모델

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

## 실제 입력의 범위와 누락

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

## 검증 및 안전성

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

## 테스트

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_day5_report
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py'
```

모의 데이터 계약 테스트와 실제 로컬 JSON의 읽기 전용 변환 테스트를 포함한다.
Git에서 제외된 Day2/3 입력이 없는 다른 체크아웃에서는 해당 로컬 통합
테스트만 입력 부재로 표시되며 모의 데이터 테스트는 계속 실행된다.
기존 Bash 문법 검사 실패는 별도 환경 문제로 기록하며 성공 처리하지 않는다.

다음 단계 증적 인덱스에는 허용된 루트·상대 경로 해석, 파일 존재 여부,
선언 해시와 실제 해시 비교, 자산/항목/채널/스냅샷 연결, 원본 시각과
검증 시각 분리 및 접근·누락 상태 기록이 필요하다. 해당 기능은 아직 없다.
