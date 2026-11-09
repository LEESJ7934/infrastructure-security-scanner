# 조치 전후 재점검 비교

`config_audit.comparison`은 공통 보고서와 기존 증적 인덱스를 입력받는
파일 접근 없는 비교 모듈이다. Collector, 진단 엔진, VM, Docker, SSH,
실장비 API 및 DB를 호출하지 않는다. 원본 상태나 증적을 변경하지 않는다.
최종 JSON/PDF 보고서 출력 기능은 이번 단계에서 추가하지 않는다.

## 입력과 실행

프로젝트 루트에서 Windows PowerShell과 가상환경 Python을 사용한다.

```powershell
@'
from pathlib import Path
from config_audit.reporting import integrate, load_snapshot
from config_audit.evidence_index import build_evidence_index, attach_evidence_index
from config_audit.comparison import SnapshotRelation, compare_snapshots

root = Path.cwd()
report = integrate([
    load_snapshot(root / "logs/day2-before.json", day=2, snapshot_id="day2-before"),
    load_snapshot(root / "logs/day2-after.json", day=2, snapshot_id="day2-after"),
    load_snapshot(root / "logs/day3-final.json", day=3, snapshot_id="day3-final"),
    load_snapshot(root / "evidence/day4/manual.json", day=4,
                  snapshot_id="day4-manual", input_kind="manual"),
])
index = build_evidence_index(report, project_root=root)
report = attach_evidence_index(report, index)
comparison = compare_snapshots(report, [
    SnapshotRelation("day2-before", "day2-after"),
])
data = comparison.to_dict()
print(data["summary"])
print(data["observed_transition_summary"])
print(data["unpaired_snapshot_ids"])
'@ | .\.venv\Scripts\python.exe -B -
```

`SnapshotRelation`에는 before/after 스냅샷 ID와 비교 채널을 명시한다.
관계가 지정되지 않으면 결과를 생성하지 않는다. 파일명·IP·날짜를 이용해
전후 관계를 자동 추정하지 않는다. 한 관계에는 하나의 before/after 채널만
지정하며 채널별 관계를 별도로 전달할 수 있다. 같은 관계의 중복과 자기
자신과의 비교는 거부한다. 결과와 관계는 결정적으로 정렬한다.

## 비교 조건

정확히 같은 `asset_id`, `check_id`로만 대응한다. 같은 항목 ID의 다른 자산은
서로 연결하지 않고 INCOMPARABLE로 기록한다. 동일 자산·항목에 복수 결과가
있으면 규칙 버전이 달라도 하나를 고르지 않고 UNVERIFIABLE로 처리한다.

다음 정보를 모두 확인한다.

- 동일한 일차·입력 종류 및 기록된 `diagnostic_source`
- 동일 채널과 기록된 `verification_method`
- 동일한 `scope`
- 동일한 규칙 버전 또는 명시적 호환성 검토 자료
- 시간대가 명확하고 before보다 늦은 실제 진단 시각
- 비교 대상에 연결된 증적 인덱스와 읽기·무결성 상태

`reporting.py`는 새 입력에 명시된 `diagnostic_source`, `verification_method`만
보존하도록 확장했다. 기존 파일에는 값을 보충하지 않는다. 정보가 없는
두 필드는 서로 같다고 취급하지 않는다. 알려진 불일치는 INCOMPARABLE,
미확인 조건은 UNVERIFIABLE로 구분한다.

자동 채널의 `checked_at`는 기록된 진단 시각으로 사용한다. 수동 채널은
`time_basis=test_time`의 `verified_at`만 시험 시각으로 사용하며, 기록된
`validation_status=VALID`와 `attached=true`도 요구한다. 자동 판정의 규칙
버전을 수동 채널에 상속하지 않는다. `artifact_review`는 검토 시각으로
보존한다. PF/로그 분석 채널은 `time_basis=snapshot_capture_time`과
`collected_at`가 있어야 하며 분석 실행 `checked_at`를 캡처 시각으로
대체하지 않는다. 시간대 없는 시각이나 `-00:00`을 UTC로 가정하지 않는다.

## 분류와 신뢰도의 분리

| 결과 | 조건 |
|---|---|
| IMPROVED_OBSERVED | 비교 조건을 충족한 FAIL → PASS |
| UNRESOLVED | 비교 조건을 충족한 FAIL → FAIL |
| REGRESSED | 비교 조건을 충족한 PASS → FAIL |
| UNCHANGED_PASS | 비교 조건을 충족한 PASS → PASS |
| NEW_FINDING | baseline 결과는 없지만 명시적으로 검토된 동일 범위의 coverage 자료와 신규 FAIL이 있음 |
| UNVERIFIABLE | 불충분한 메타데이터, ERROR/NOT_TESTED/NEEDS_REVIEW/NOT_APPLICABLE, 증적 문제 등 |
| INCOMPARABLE | 자산·규칙·범위·검증 방식·출처·채널 또는 시각 순서의 알려진 불일치 |
| MISSING_IN_RETEST | 정상적으로 읽은 재점검 스냅샷에서 최초 항목이 누락됨 |

입력 파일을 읽지 못한 경우를 항목 누락으로 처리하지 않는다. 관계의 입력
부재·중복은 관계 수준의 오류로도 기록한다. 양쪽에 항목이 전혀 없으면
가짜 진단 항목을 만들지 않으므로 항목 요약과 `invalid_relation_count`를
함께 확인해야 한다.

`comparison_result`는 엄격한 최종 분류다. `recorded_transition`은 원래
상태 두 개이고, `observed_change`는 알려진 비교 조건의 불일치가 없을 때
기록상 보이는 `FAIL_TO_PASS` 등의 원본 상태 변화다. 최종 분류 이름을
재사용하지 않는다. 미확인 조건 때문에 최종 결과가 UNVERIFIABLE여도
보조 필드의 FAIL→PASS는 유지할 수 있다. 보조 변화 건수를 최종 개선
건수로 합산하면 안 된다.

`comparability.status`와 `metadata_status`를 구분하여, 메타데이터가
대응하더라도 증적 때문에 비교할 수 없는 경우를 표현한다. 증적은
before/after 각각 참조·인덱스 항목·상태 개수·신뢰도·오류를 보존한다.
MISMATCH/MISSING/INVALID_REFERENCE와 읽기 오류는 최종 비교를 차단한다.
파일이 읽혔으나 독립 기대 해시가 없는 NOT_VERIFIED는 그대로 유지하고
신뢰도 LIMITED로 표시한다. 입력 JSON만 있는 경우에는 저장 결과를
확인했을 뿐 개별 시험 원본이 없다는 한계도 기록한다. 다른 자산이나
다른 채널의 VERIFIED 증적은 현재 항목의 검증으로 사용하지 않는다.

이 모듈은 조치 이력을 입력받거나 검증하지 않으므로
`remediation_history_confirmed=false`를 기록한다. IMPROVED_OBSERVED도
실제 조치 수행이나 그 인과관계를 확인했다는 의미가 아니다.

## 명시적인 검토 자료

`RuleCompatibility`는 자산·항목·채널·전후 버전·범위·출처·검증 방식과
검토자·검토 시각·증적 ID를 요구한다. 해당 증적은 인덱스에서 동일 관계에
속한 `role=rule_compatibility_review`이며 독립 기대 해시와 일치해야 한다.
여러 검토가 중복되거나 범위 등이 다르면 버전 불일치를 해제하지 않는다.

`BaselineCoverage`는 누락된 최초 결과를 PASS로 생성하지 않는다. 동일
자산·항목·채널의 baseline 범위·버전·출처·방식·시각과 검토 정보를
명시해야 하며, 최초 스냅샷에 연결된 `role=baseline_coverage` 증적의
무결성이 확인되어야 NEW_FINDING을 허용한다. 이 분류는 신규로 기록된
FAIL이며 과거에 PASS였다는 주장은 아니다.

두 선언의 의미상 검토는 호출자가 명시적으로 제공하는 신뢰 경계다.
코드는 증적 연결·해시·메타데이터 일관성을 확인하지만 검토 문서 본문의
의미를 읽거나 자동 입증하지 않는다. 해시 일치만으로 호환성이나 coverage
검토를 추론하지 않으며 실제 Day2 데이터에는 이런 선언을 추가하지 않았다.

## 실제 Day2 결과

| 항목 | 최초 | 재점검 | 기록상 변화 | 엄격한 결과 |
|---|---|---|---|---|
| LAB-SSH-001 | PASS | PASS | PASS_TO_PASS | UNVERIFIABLE |
| LAB-SSH-002 | FAIL | PASS | FAIL_TO_PASS | UNVERIFIABLE |
| LAB-MYSQL-001 | PASS | PASS | PASS_TO_PASS | UNVERIFIABLE |
| LAB-MYSQL-002 | FAIL | PASS | FAIL_TO_PASS | UNVERIFIABLE |

자산 ID, 규칙 버전 1, 자동 채널과 진단 시각 순서는 일치한다. 하지만 원본에
`scope`, `diagnostic_source`, `verification_method`가 없어서 엄격한 요약은
UNVERIFIABLE 4건이다. 최종 개선·미해결·악화·양호 유지 건수는 각각 0이다.
보조 원본 변화는 FAIL→PASS 2건, PASS→PASS 2건이다.

Day2 입력 JSON은 존재하고 해시를 계산했지만 독립 기대 해시가 없어
각 연결은 NOT_VERIFIED이며 비교 증적 신뢰도는 LIMITED다. 조치 이력과
개별 시험 원본도 확인되지 않았다. 원본을 소급해서 보강하지 않았다.
Day3/Day4는 전후 관계가 없어 `unpaired_snapshot_ids`에만 기록한다.
FW-04/05 NEEDS_REVIEW와 FW-06 수동 PASS 등 원본 상태는 그대로 유지한다.

## 테스트와 다음 보고서 통합

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_remediation_comparison
.\.venv\Scripts\python.exe -B -m unittest tests.test_remediation_comparison tests.test_evidence_integrity tests.test_offline_reporting
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py'
```

최종 JSON/PDF에는 원본 `OfflineReport.to_dict()`, 증적 인덱스,
별도 `ComparisonReport.to_dict()`를 입력하는 구조가 필요하다. 비교 요약과
보조 원본 변화 요약을 분리하고 관계·미대응 스냅샷·미확인 조건·증적 신뢰도·
원래 진단 시각·증적 검증 시각·비교 생성 시각을 함께 표시해야 한다.
조치 이력은 향후 독립적인 출처와 확인 절차를 갖춘 별도 입력이 필요하다.
