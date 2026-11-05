# Day5 3단계: 증적 인덱스와 SHA-256 무결성 검사

`config_audit.evidence_index`는 공통 보고서 모델의 증적 참조와 명시적으로
추가한 파일만 읽는다. 디렉터리 자동 탐색, 진단 재평가, 외부 명령 실행,
실장비 접속을 하지 않는다. 파일 내용은 출력하거나 수정하지 않는다.

## 사용 방법

프로젝트 루트에서 Windows 가상환경 Python으로 실행한다.

```powershell
@'
from pathlib import Path
from config_audit.reporting import integrate, load_snapshot
from config_audit.evidence_index import (
    EvidenceBinding, build_evidence_index, attach_evidence_index,
)

root = Path.cwd()
report = integrate([
    load_snapshot(root / "logs/day2-before.json", day=2, snapshot_id="day2-before"),
    load_snapshot(root / "logs/day2-after.json", day=2, snapshot_id="day2-after"),
    load_snapshot(root / "logs/day3-final.json", day=3, snapshot_id="day3-final"),
    load_snapshot(root / "evidence/day4/manual.json", day=4,
                  snapshot_id="day4-manual", input_kind="manual"),
])

# 명시적인 보조 자료 연결이며, 저장된 PF 분석 결과를 새로 만들지 않는다.
extra = [EvidenceBinding(
    "evidence/day4/fw04-active-rules.txt", asset_id="SJ-D4-OPNsense",
    check_id="FW-04", day=4, snapshot_id="day4-manual", channel="pf",
    role="supporting_artifact_without_saved_analysis",
)]
index = build_evidence_index(report, project_root=root, extra_bindings=extra)
indexed_report = attach_evidence_index(report, index)
print(index["counts"])
print("unique local files:", index["unique_local_files"])
'@ | .\.venv\Scripts\python.exe -B -
```

최종 보고서 CLI나 PDF 기능은 추가하지 않는다. `indexed_report.to_dict()`는
JSON 직렬화 가능한 공통 모델이며 보고서 생성 시각은 그대로 유지한다.

## 연결 방식

- `report_bindings()`는 각 결과의 자동·수동·PF·로그 분석 채널에서
  `evidence_references`를 가져온다. 원래 자산, 항목, 일차, 스냅샷,
  규칙 버전 및 채널을 보존한다.
- `snapshot_input`은 결과가 읽힌 입력 JSON 자체에 대한 연결이다.
  원본 설정이나 실제 시험 패킷의 증명으로 간주하지 않는다.
- `extra_bindings`는 호출자가 명시한 추가 연결이다. 대응 항목이 입증되지
  않은 자료에는 자산·항목을 비워 두고 `local_artifact`를 사용한다.
- PF/원시 로그 파일의 보조 연결은 분석 결과가 아니다. 기존 `analyses`에
  새 PASS나 NEEDS_REVIEW를 생성하지 않는다.
- `attach_evidence_index()`는 새 보고서 모델을 반환한다. 원래 판정과
  채널 데이터는 유지하며 결과별 `evidence_index_ids`에 채널별 ID를 추가한다.
  원래 증적 참조의 2단계 `NOT_VERIFIED` 표시는 과거 변환 메타데이터로
  유지하고, 이번 검증 결과는 연결된 인덱스 항목에서 확인한다.

동일 파일이라도 서로 다른 자산·항목·스냅샷·채널의 연결은 각각 유지한다.
완전히 같은 연결·참조·기대 해시 선언만 중복 제거한다. 경로 표기나 기대
해시 선언이 다른 연결을 자동 병합하지 않는다. 정렬과 ID는 내용 해시나
실행 시각에 의존하지 않으므로 파일 변조 전후에도 같은 연결 ID를 유지한다.

## 인덱스 필드와 상태

각 항목에는 `evidence_id`, 자산/항목/일차/스냅샷/채널/규칙 버전/역할,
`original_reference`, `relative_to`, `local_path`, `exists`, `size_bytes`,
`actual_sha256`, `expected_sha256`, `expected_hash_source`, `hash_comparison`,
`status`, `verified_at`, `error`, `limitations`를 기록한다.
미확인 존재 여부는 `null`이며 외부·거부 경로를 존재한다고 주장하지 않는다.

| 상태 | 의미 |
|---|---|
| VERIFIED | 파일을 읽었으며 제공된 독립 기대 SHA-256과 일치 |
| MISMATCH | 파일을 읽었으나 기대 SHA-256과 불일치 |
| MISSING | 허용된 로컬 파일 경로이나 파일이 없음 |
| NOT_VERIFIED | 파일 존재는 확인했으나 독립 기대 해시가 없거나 읽기·변경·크기 검증 오류가 있음 |
| EXTERNAL_REFERENCE | 컨테이너/외부 시스템의 불투명 참조이며 로컬 접근을 하지 않음 |
| INVALID_REFERENCE | 금지 경로, 링크, 민감 파일, 잘못된 참조/기대 해시 등 |

기대 해시가 없는 파일도 실제 해시는 계산하지만 이를 기대 해시로 복사하지
않는다. Day4 수동 JSON의 선언된 해시는 `stored_reference_declaration`으로
출처를 구분한다. PF 분석의 `source_integrity_claims`에 들어 있는 계산
해시를 독립 기대 해시로 승격하지 않는다. 해시 선언 자료 자체의 진위는
이번 검사로 입증되지 않으며 동일 파일을 여러 번 확인해도 진위나 수집
완전성이 보장되지 않는다.

`generated_at`는 기존 보고서 생성 시각이고 `verified_at`는 이번 실제
검증 실행 시각이다. 파일 수정 시각을 시험·수집 시각으로 대체하지 않는다.

## 파일 접근 경계

신뢰할 프로젝트 루트 내부에서도 다음 경로만 허용한다.

- 단일 파일: `logs/day2-before.json`, `logs/day2-after.json`, `logs/day3-final.json`
- 증적 트리: `lab/day3/artifacts/`, `evidence/day4/`

허용 트리는 탐색 요청을 뜻하지 않는다. 입력에서 명시한 파일만 읽는다.
`.env*`, `.git`, SSH 키 이름, 개인키 확장자, 자격증명·Secret·Token 파일
이름은 허용 트리 내부에서도 거부한다. 인증 문자열이 참조에 들어 있으면
오류 결과에서도 참조를 마스킹한다. OS 예외 메시지나 파일 본문은 반환하지 않는다.

`..`, 범위 밖 절대 경로, 다른 드라이브, 드라이브 상대 경로, UNC/장치 경로,
NTFS 대체 스트림, 모호한 Windows 파일명, 심볼릭 링크·junction·reparse
point 및 하드 링크를 거부한다. 상대 경로 기준도 프로젝트 내부여야 한다.
Windows는 열린 핸들의 최종 경로와 파일 ID를 읽기 전에 확인하고 쓰기/삭제
공유를 허용하지 않는다. POSIX는 디렉터리 핸들 기준 no-follow로 접근한다.
읽기 전후 파일 ID·크기·수정 시각을 비교한다. Windows의 경로/핸들 조회 간
`ctime` 의미 차이를 파일 변경으로 오인하지 않도록 처리한다.

연결 16,384건, 파일당 64 MiB, 실행당 보수적인 읽기 예산 256 MiB로
제한한다. 제한·읽기 오류·변경 감지는 VERIFIED가 될 수 없다. 허용 경로에
예상하지 못한 파일을 추가하지 않는 운영 관리도 필요하다.

## 실제 로컬 자료 확인 결과

Day2 전후 입력 2개, Day3 입력 1개와 로컬 아티팩트 3개, Day4 수동 입력을
포함한 17개 증적 파일 집합을 명시적으로 확인했다. Day4 17개에는 수동 입력 자체가
포함된다. 실제 고유 로컬 파일은 총 23개다. Day3 로컬 아티팩트는 자동
컨테이너 참조와 동일하다고 입증되지 않아 별도 미배정 자료로 등록했다.

자산·항목·채널별 연결 기준 60건: VERIFIED 15, NOT_VERIFIED 33,
EXTERNAL_REFERENCE 12, MISMATCH/MISSING/INVALID_REFERENCE 각 0.
고유 파일 기준으로는 수동 증적 11개가 선언 해시와 일치하며, 나머지
12개 파일은 이번 입력에 독립 기대 해시가 제공되지 않았다.

FW-02/03 수동 PASS, FW-04/05 수동 NEEDS_REVIEW, FW-06 수동 PASS를
보존했다. 완전한 Day4 자동 실행 결과가 없어 `automatic=null`을 유지한다.
새 자동 결과, PF/로그 판정, 규칙 연속성 또는 새로운 실장비 시험을
만들지 않았다. 참조된 허용 로컬 파일 중 누락·불일치는 없지만 Day3의
외부 참조 12건은 로컬 증적으로 해결되지 않은 상태다.

## 테스트와 다음 단계

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_day5_evidence tests.test_day5_report
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py'
```

임시 파일 계약 테스트 및 실제 수동 증적 해시 검사를 포함한다. Windows에서
심볼릭 링크 생성 권한이 없으면 해당 링크 경계는 모의 lstat로 검사하며,
reparse point 경계도 모의 응답으로 별도 검사한다. 실제 로컬 파일 검증에는
Windows 핸들 경로 검사를 사용한다. Git에서 제외된 Day3 입력이 없는 다른
체크아웃에서는 그 로컬 통합 테스트만 입력 부재를 표시한다.

다음 재점검 비교 단계에는 자산/항목/규칙 버전과 스냅샷의 명시적인 전후
관계, 채널별 비교, 수집·검증 시각 구분, 증적 상태와 진단 상태의 분리,
누락·버전 변경·수동 범위 차이를 검증 불가로 표현하는 정책이 필요하다.
해시 일치 자체를 조치 완료나 진단 PASS로 취급하면 안 된다.
