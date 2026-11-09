# FW-05 — 저장 로그와 실제 PF 규칙의 제한 범위 연계

대상: `C:\Projects\infrastructure-security-scanner-clone`, 브랜치 `feature/day4-opnsense`. 날짜: 2026-11-06 (Asia/Seoul).

## 변경 파일과 보존 범위

- 추가 `config_audit/collectors/opnsense_log_rules.py`: 저장 로그·PF·시간/시험 맥락을 대조하고 기존 evaluate()로 별도 FW-05 증적 판정.
- 수정 `scripts/run_day4_audit.py`: 선택적인 FW-05 입력과 분리된 결과 출력.
- 추가 `tests/test_day4_log_rule_evidence.py`: 합성 데이터 unittest 23개.
- 추가 본 문서, 수정 `docs/opnsense-audit.md`.

기존 API 수집기와 limit=20, IncompleteRead 처리, TLS/CA 검증, FW-01~04/FW-06 판정, 수동 증적 판정기는 변경하지 않았다. 실제 API/방화벽/계정 권한을 건드리지 않았으며 commit/push도 하지 않았다. 실제 로그·PF·manual.json은 읽기만 했고 수정하거나 Git에 추가하지 않았다.

## 네 가지 상태를 분리한다

`results` 중 FW-05의 기존 `status`, `automatic_status`, `api_results`, `rule_id_mapping`, `manual_verification`은 그대로 둔다. 새 `log_rule_evidence`에서 다음을 별도로 기록한다.

| 필드 | 의미 |
|---|---|
| automatic_collection | 이번 실행의 실제 로그 API 수집 상태. --execute 없는 실행은 NOT_TESTED |
| api_rule_id_mapping | 이번 실행의 list_rule_ids 조회/매핑 상태. HTTP 403은 기존 api_results의 HTTP 코드 및 이 ERROR 상태로 남음 |
| log_file_collection | 저장 JSON 파싱/수집 상태. live API 조회 성공과 동일하지 않음 |
| rule_mapping | rid/PF label, 규칙 의미, 상세 위치와 과거 시점 연속성을 함께 고려한 매핑 상태 |
| status | 기존 evaluate()가 반환한 이 한정 시험의 증적 기반 검증 상태 |

로컬 매핑이 성공해도 API 403을 덮어쓰지 않으며, 저장 파일이 존재한다고 live API COLLECTED나 최종 PASS를 만들지 않는다. --execute 없이 기존 403을 다시 측정했다고 기록하지 않는다. 알려진 이전 403은 과거 사용자 보고이고, 이번 실행의 API 상태는 NOT_TESTED다. API 로그 수집 200과 ID 조회 403의 독립 처리는 Mock 통합 테스트로 검증했다.

## 실제 파일과 결과

실제 저장 로그는 1,407바이트이며 SHA-256은 `cde64f0b88f55739c63c2530f59e8bfa75998c6277ab11265334089414ee44f1`이다. JSON 최상위 객체의 logs 배열 3건을 읽었다. 최상위 list도 지원한다. 이번 로그 해시는 현재 파일의 바이트에서 직접 계산해 대조한 기준값이며 별도의 서명/과거 공개 해시가 있는 것은 아니다. 해시는 바이트 동일성을 확인할 뿐 기록 출처의 진실성이나 시험 시점을 자동 증명하지 않는다.

PF 일반/상세 파일은 기존 실제 archive와 member 바이트 일치 및 독립적으로 제공된 archive SHA-256으로 확인했다.

| 파일 | SHA-256 |
|---|---|
| fw04-active-rules.txt | 6efaac2b285f0b677da6d018eedf40b598814eba7d11dc6c50504979d3d7719a |
| fw04-active-rules-detail.txt | dd3da77ccfb1cceb98631205800f01cbe20ce347e99b4ca6e935ead0a8bdb495 |
| fw04-rules.tar | b0ca18a9de3c701c5b7e63cec45443c7b544c8ded2d44595f644463837fcb8af |

실제 로컬 분석 결과:

- log_file_collection=COLLECTED, 3건.
- 출발지 10.77.50.10, 목적지 10.77.50.1, TCP/22, hn0, Action block 모두 일치. 로그의 source port는 세 건 모두 41993.
- 이벤트 시각 2026-11-05T17:53:39~41은 사용자가 지정한 **동일한 벽시계 표시 범위**와 일치.
- 로그 rid와 PF label 값이 일치하고, IPv4/Direction/Action/주소/포트 의미를 대조하면 후보가 하나다. 일반 필터 순서와 상세 @6도 일치한다. IPv6에 같은 label이 있어도 family와 실제 패킷 조건으로 구별한다.
- 로그 label `Default deny / state violation rule`은 PF 후보의 IPv4 전체 차단 형태와 일관된다. 하지만 GUI 설명을 권위 있는 PF 식별자 매핑으로 인증했다는 뜻은 아니다.
- identity_match=true이지만 historical_continuity_verified=false이므로 rule_mapping=NEEDS_REVIEW.
- 최종 증적 기반 FW-05는 **NEEDS_REVIEW**이며 다음 세 조건이 부족하다.

```text
test_execution_context_missing
log_timezone_unverified
snapshot_test_continuity_unverified
```

저장 JSON의 captured_at_utc는 파일 수집 메타데이터이며 개별 로그 시각의 시간대가 아니다. 이벤트의 __timestamp__에는 offset이 없다. UTC/한국 시각으로 임의 해석하거나 파일 mtime, PF Last Active Time을 시험 당시 정책 세대의 증거로 삼지 않았다. 현재 실행 ID는 분석 참조일 뿐 과거 로그의 트래픽 실행 ID가 아니다.

원본 파일의 endpoint는 limit=50으로 기록되어 있다. 이는 과거 파일에 적힌 수집 경로이며, 현재 live API 수집기의 limit=20은 변경하지 않았다. 원본 label/rid/임의 추가 필드/원본 경로/응답 본문은 새 보고서에 복사하지 않는다. 고정된 실습 대상, 검증된 시각 문자열, 숫자, 불투명한 PF 참조 및 고정 사유 코드만 출력한다.

## 오프라인 실행

```powershell
Set-Location 'C:\Projects\infrastructure-security-scanner-clone'
.\.venv\Scripts\python.exe -B -m scripts.run_day4_audit `
  --fw05-log-evidence '.\evidence\day4\fw05-wan-tcp22.json' `
  --fw05-log-sha256 cde64f0b88f55739c63c2530f59e8bfa75998c6277ab11265334089414ee44f1 `
  --fw05-test-start '2026-11-05T17:53:39' `
  --fw05-test-end '2026-11-05T17:53:41' `
  --pf-rules-evidence '.\evidence\day4\fw04-active-rules.txt' `
  --pf-rules-detail '.\evidence\day4\fw04-active-rules-detail.txt' `
  --pf-rules-archive '.\evidence\day4\fw04-rules.tar' `
  --pf-rules-archive-sha256 B0CA18A9DE3C701C5B7E63CEC45443C7B544C8DED2D44595F644463837FCB8AF `
  --manual-evidence '.\evidence\day4\manual.json'
```

이 명령은 외부 명령/Ping/API를 실행하지 않는다. 종료 코드 0은 오프라인 분석 명령의 정상 종료이며 최종 PASS를 뜻하지 않는다. 해시 불일치/구조 오류는 ERROR와 종료 코드 1이며 --execute가 함께 지정돼도 API 요청 전에 중단한다. 원래 API 판정 및 수동 FAIL/충돌의 종료 코드 처리도 유지한다.

PF archive 대신 기존 `--pf-rules-sha256` / `--pf-rules-detail-sha256`으로 두 파일을 각각 고정할 수 있다. 기대 해시가 없으면 파싱하되 무결성 미고정 사유가 남는다. 파일을 읽자마자 계산한 해시만으로 원본 출처의 독립적 진위를 증명했다고 주장하지 않는다.

## 제한 범위 PASS 조건과 후속 자료

대상 범위는 `historical_10.77.50.10_to_10.77.50.1_tcp22_block_only`다. WAN→LAN 전달, 모든 포트, 전체 로그 정책, 현재의 실제 정책/트래픽 검증을 뜻하지 않는다. 필요한 파일·규칙 매핑·시각·시험 결과의 모든 조건이 충족된 때만 이 범위의 PASS를 반환한다. 잘못된 Action/주소/포트/시각/식별자 또는 규칙 변경 가능성이 해소되지 않으면 NEEDS_REVIEW이고 파일 손상은 ERROR다. 숫자 rulenr만으로 규칙을 연결하지 않는다.

추후 신뢰할 수 있는 독립 수집기가 시험 맥락까지 함께 확보하면 `--fw05-test-context PATH --fw05-test-context-sha256 SHA256`으로 제출할 수 있다. 현재 실제 자료에는 이러한 context가 없으므로 생성하지 않았다. 이 JSON은 **프로젝트의 정규화된 신뢰 수집기 계약**이며 실제 OPNsense API에서 확인된 필드가 아니다. 단지 PASS를 얻으려고 손으로 세대 값을 채우거나 before/after의 규칙 텍스트 해시만 같다는 이유로 연속성이 입증됐다고 입력해서는 안 된다.

필수 계약은 다음과 같다. 알 수 없는 키와 잘못된 타입은 거부한다.

| 객체 | 필수 키/의미 |
|---|---|
| 최상위 | schema_version=1, test, log_clock, capture_session |
| test | source, destination, protocol, destination_port=22, source_port, interface=hn0, actual_result=timeout, started_at, finished_at. 주소·프로토콜은 이 문서의 고정 시험 대상과 같아야 함 |
| log_clock | offset(확인된 장비 offset, ±HH:MM), basis=trusted_collector_device_clock. 이벤트 자체에 offset이 없을 때만 이 확인된 offset으로 해석 |
| capture_session | session_id(32자리 소문자 hex), log_sha256, rules_sha256, detail_sha256, before_at, after_at, rules_captured_at, generation_before, generation_at_snapshot, generation_after, basis=trusted_collector_ruleset_generation |

각 generation은 신뢰 수집기가 확보한 **정책 재적용/세대를 구분할 수 있는 동일 수집 맥락의 증거 식별값**(정규화 64자리 hex)이어야 한다. 이 코드는 OPNsense에 그런 이름의 API 필드가 있다고 가정하지 않으며 원본 세대 값을 스스로 만들어 내지 않는다. 세대 변경을 구분하지 못하는 checksum의 단순 반복이나 운영자 추정은 적합한 계약 입력이 아니다. 운영 환경에서 이런 수집기의 출처/정확성이 검증되지 않았다면 context를 제출하지 않고 NEEDS_REVIEW를 유지해야 한다. 파일 해시만으로 수집기 인증/내용 진위를 암호학적으로 증명하지 못한다는 한계도 결과에 남긴다.

before_at ≤ 시험 시작 ≤ 시험 끝 ≤ after_at, before_at ≤ PF 수집 시각 ≤ after_at을 확인한다. 해당 수집 세션이 로그 파일의 수집 시각도 포함해야 한다. 이벤트 시각은 확인된 timezone으로 해석한 뒤 시험 구간 안에 있어야 하고, source port도 실제 시험과 일치해야 한다. 세대 세 값이 모두 일치하고 원본 로그/PF/상세 파일 해시가 정확히 연결되어야 과거 연속성을 승인한다. 기존 세대/현재 세대가 다르면 rid/순번이 여전히 같더라도 NEEDS_REVIEW다.

이 계약은 과거에 없던 데이터를 소급해 만들라는 지침이 아니다. 장비의 시간대/시각 동기화 자료, 실제 시험 실행 기록(시작/끝/출발 포트/Timeout), 시험 전후 정책 세대 및 PF 캡처를 안전한 조회 전용 수집으로 확보해야 한다. generation의 정확한 수집 방법은 해당 설치 버전과 검증된 수집기에 맞게 정해야 한다. 현재 이미 확보한 API 자료만으로 이 부분이 입증됐다고 주장하지 않는다. API 권한을 올리거나 방화벽 정책을 변경할 필요는 없으며, 권한이 부족한 ID API 403은 계속 별도 상태로 남긴다.

## 테스트

신규 unittest 23개: 충분한 합성 context의 한정 PASS, 기존 evaluate() 호출, rid/순번/의미 매칭, 숫자만 일치하는 경우 거부, Action·튜플·출발 포트·시간·시간대 불일치, -00:00의 unknown offset 처리, 과거 규칙 세대 변경, 파일 변조/누락/잘못된 JSON, 중복 rid, label과 PF default-deny 형태 불일치, 비밀/경로 비출력, 오프라인 무통신, live 로그 수집과 ID 403 독립 처리를 검증했다. 실제 장비 로그를 테스트 fixture로 Git에 넣지 않았다.

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_day4_log_rule_evidence tests.test_day4_pf_evidence tests.test_day4_audit tests.test_day4_manual_evidence -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py'
```

Day4 162개 모두 통과. 전체 543개 중 542개 통과. 기존 `test_ec2_owner_deployment_script_syntax` 한 개는 Git Bash의 Windows 샌드박스 객체 생성 제한(0xC0000022)으로 실패했다. 기존 테스트 수정/삭제/skip 또는 pytest 설치로 결과를 우회하지 않았다.
