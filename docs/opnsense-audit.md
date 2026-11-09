# OPNsense 방화벽 설정 진단 및 검증

최종 수정일: 2026-11-06 (Asia/Seoul). 대상 저장소: `C:\Projects\infrastructure-security-scanner-clone`, 브랜치: `feature/day4-opnsense`.

이번 수정은 사용자가 직접 확인한 26.7의 HTTP 상태·최상위 구조·필드 목록을 반영했다. 이 개발 세션에서는 실제 장비에 접속하지 않았다. 내부 config/flags/주소 필드의 실제 값과 의미는 아직 제공되지 않아 이를 추측하는 어댑터는 추가하지 않았다.

### FW-05 응답 잘림 보완

사용자는 `/api/diagnostics/firewall/log?limit=20`이 HTTP 200, 16,779바이트, 약 0.06초로 정상 수신되고, limit 없는 조회는 약 0.08초 후 `http.client.IncompleteRead`가 발생했다고 보고했다. 기존 코드는 로그 조회에 limit가 없고 requests의 포괄적 예외를 `api_connection_failed`로 처리했다.

이제 `ReadOnlyClient.get("logs")`에만 `params={"limit": 20}`을 지정한다. 초기 수집과 Ping 이후 재조회 모두 같은 경로를 사용하므로 제한이 적용된다. interfaces_info/export/rules/rule_ids/get_rule 등 다른 API의 요청 인자는 변경하지 않았다. 실패 시 무제한 재조회나 TLS 우회를 하지 않는다.

원본 `IncompleteRead`, requests의 `ChunkedEncodingError`, 예외 체인/인자 안에 감싸진 `IncompleteRead`는 `api_incomplete_response`, 단계 `response_read`로 기록한다. 예외 메시지와 partial body는 읽어 출력하지 않는다. HTTP 상태를 실제 확보한 뒤 잘림이 발생하면 상태 코드를 보존하고, requests.get 내부에서 실패해 Response가 반환되지 않으면 http_status=null로 남긴다. 사용자가 보고한 HTTP 200을 실행 중 관찰값으로 임의 주입하지 않는다. JSON 파싱 실패는 기존 `api_json_invalid`/`json_parse` ERROR이며 HTTP 200 자체를 수집 성공으로 간주하지 않는다.

로그 조회가 성공해도 현재 허용/차단 이벤트·점검 규칙과 연계되지 않으면 FW-05는 NEEDS_REVIEW다. rule_ids의 403은 별도로 기록되며 성공한 로그 수집 또는 로그 잘림 오류를 덮어쓰지 않는다. FW-01~04/FW-06 판정 함수와 실행 스크립트는 이번 보완에서 변경하지 않았다. FW-01 PASS 유지도 Mock 통합 테스트로 확인했다.

## A. 추가 파일과 변경 범위

- `config_audit/collectors/opnsense.py`: 조회 전용 API 클라이언트, 인터페이스 응답 어댑터, 로그 스냅샷 검사, 정규화 증거 기반 수집기, 별도 승인 Ping 함수.
- `scripts/run_opnsense_lab_audit.py`: 준비 모드, `--execute`, `--ping`, 시나리오 선택, 기존 `evaluate()` 연결 및 안전한 JSON 출력.
- `tests/test_opnsense_lab_audit.py`: 기존 Day4 테스트 79개 유지, 로그 요청/응답 보완 9개 추가, 총 88개.
- `docs/opnsense-audit.md`: 본 구현·검증·실행 보고서.
- `config_audit/manual_evidence.py`: 수동 입력의 엄격한 구조 검사, 로컬 첨부 SHA-256 확인, 자동/수동 결과 분리와 충돌 표시.
- `examples/opnsense-manual-evidence.template.json`: 증적 미첨부 상태의 빈 입력 템플릿.
- `tests/test_opnsense_manual_evidence.py`: 수동 증적 연계 테스트 26개. 기존 88개 테스트는 변경하지 않았다.

기존 Day 1~3 코드, 공통 모델·판정 엔진, 기존 381개 테스트는 변경하지 않았다. 의존성 추가 없이 기존 requests와 표준 라이브러리를 사용한다. Docker 변경, Hyper-V 조작, 실제 방화벽 API 호출, 실제 Ping, Git commit/push는 수행하지 않았다.

## B. FW-01~06 구현 내용

여섯 항목 모두 수집 결과를 `Observation`으로 전달하고 기존 `config_audit.engine.evaluate()`로 판정한다. 별도 상태 판정 엔진을 만들지 않았다. 정규화 패킷 사례에 적용되는 규칙 선택 함수는 FW-04의 관찰값을 만드는 분석 함수다.

| 항목 | 판정 기준과 검증 범위 |
|---|---|
| FW-01 | LAN=`hn1 / 10.77.40.1/24`, WAN=`hn0 / 10.77.50.1/24`. interfaces_info의 dict/rows와 export의 list를 각각 검사한다. 한 소스 실패가 다른 소스의 유효 증거를 무효화하지 않는다. identifier/device로 할당을 확인하고, 명시적으로 이해 가능한 enabled/status/IPv4 CIDR이 모두 있는 경우에만 PASS 가능하다. 제공된 필드 목록만으로는 활성·IP를 증명할 수 없어 NEEDS_REVIEW. get_interface_config는 호출하지 않는다. |
| FW-02 | WAN `10.77.50.10 → 10.77.50.1 TCP/443` 시험만 인정. 허용은 FAIL. 차단 PASS는 정상 대조 시험과 현재 실행의 일치하는 차단 로그가 필요. LAN 관리 접속 및 규칙 내용만으로 WAN 차단을 확정하지 않는다. WAN 시험이 없으면 NOT_TESTED. |
| FW-03 | 승인 ICMP `10.77.50.10 → 10.77.50.1` 허용과 비인가 TCP/22 차단을 별도 확인. 두 실제 시험과 일치 로그가 필요하고 차단에는 정상 대조 증거도 요구. 시험이 없으면 NOT_TESTED. PASS는 이 샘플 범위에만 해당하며 모든 포트·호스트의 차단을 의미하지 않는다. |
| FW-04 | 전체 유효 정책의 적용 범위가 확인된 정규화 IPv4 inbound 규칙에 한해 분석. 활성 여부·전체 순서·Quick·출발지·목적지·프로토콜·포트를 반영. Quick은 최초 일치에서 종료하고 non-Quick은 마지막 일치를 선택. 비활성 실습 Block은 제외하며 LAN 기본 허용과 WAN 제한을 구분. |
| FW-05 | 로그 GET의 수집 결과와 list_rule_ids의 조회/매핑 결과를 별도로 기록한다. ID API의 403은 성공한 로그 수집을 ERROR로 덮어쓰지 않는다. 실제 로그와 현재 실행 Probe의 튜플·Action·시간·가능한 rule ID 대조는 계속 요구하므로 로그 존재만으로 PASS하지 않는다. |
| FW-06 | Windows `10.77.40.10 → Alpine 10.77.50.10 ICMP`. pass/block 기대와 실제 결과 비교 후 로그 대조. 미실행은 NOT_TESTED, 기대 불일치는 FAIL, 성공 Ping만 있거나 로그가 없으면 NEEDS_REVIEW. 정책은 변경하지 않는다. |

FW-04의 다섯 고정 사례:

1. WAN 승인 호스트 `.50.10`의 방화벽 WAN 주소 대상 ICMP: pass.
2. 같은 WAN 호스트의 TCP/443: block 또는 reject.
3. 같은 WAN 호스트의 TCP/22: block 또는 reject.
4. 다른 WAN 호스트 `.50.11`의 ICMP: block 또는 reject. 이 사례는 오프라인 분석용이며 해당 주소로 네트워크 접근하지 않는다.
5. LAN Windows `.40.10`의 Alpine `.50.10` 대상 ICMP: 기본 pass. 현재 실행에 명시된 동일 경로 block 시험이 있을 때 block.

이 다섯 사례는 전수 정책 증명이 아니다. 별칭, floating/group, 자동 생성 규칙, 방향, NAT, schedule, IPv6, state 등에 대한 실제 변환 및 전체 적용 순서가 확인되지 않으면 `complete_rules=False`로 유지한다. 누락된 기본 차단은 임의로 생성하지 않는다. 동일 순서/ID 또는 미해결 별칭 등 해석할 수 없는 입력은 ERROR/NEEDS_REVIEW이며 PASS로 축약하지 않는다.

각 결과에는 `asset_id`, `check_id`, `status`, `execution_id`, `checked_at`, `evidence_reference`, `reason`이 포함된다. `evidence_reference`는 `day4:<run>:<check>` 형태의 비밀 없는 실행 참조이며 원본 증거 파일을 저장했다는 뜻이 아니다. 공통 `to_safe_dict()`를 사용하고, 관련 항목에는 안전한 `api_results`, FW-04의 `scope`, FW-05의 `rule_id_mapping`을 추가한다. 원본 설정, 응답 본문, API 인증 정보, Authorization 헤더, Ping stderr는 출력하지 않는다.

상태는 기존 PASS / FAIL / NEEDS_REVIEW / NOT_APPLICABLE / NOT_TESTED / ERROR를 그대로 사용한다. 제품 불일치는 기존 엔진이 NOT_APPLICABLE로 처리한다. 기본 준비 모드는 모든 항목 NOT_TESTED이며 종료 코드 0은 준비 명령의 정상 종료일 뿐 방화벽 진단 PASS가 아니다. FAIL/ERROR가 있으면 종료 코드 1이다.

## C. 공식 API와 모의 응답 구분

이전 공식 문서/core 소스 조사와 이번 사용자 제공 장비 관찰을 구분한다. master 소스나 합성 fixture를 설치된 26.7의 완전한 응답으로 간주하지 않는다. 사용자가 확인한 사실은 다음과 같으며, 이 세션에서 재호출하지 않았다.

| Endpoint | 사용자 확인 HTTP/구조 |
|---|---|
| interfaces/overview/interfaces_info | 200, dict 내부 rows=list |
| interfaces/overview/export | 200, 최상위 list |
| diagnostics/firewall/log | 200, 접근 가능; 실제 내부 값/전체 스키마는 미제공 |
| diagnostics/interface/get_interface_config | 403 |
| diagnostics/firewall/list_rule_ids | 403 |
| firewall/filter/search_rule | 403 |

확인된 overview rows 필드는 `flags`, `capabilities`, `options`, `macaddr`, `supported_media`, `is_physical`, `device`, `mtu`, `groups`, `nd6`, `routes`, `config`, `status`, `identifier`, `description`이다. config 내부 경로나 flags 값의 의미는 가정하지 않는다. description을 LAN/WAN 식별자로 쓰거나 배열 순서로 두 응답을 결합하지 않는다. IP에 prefix가 없으면 /24를 덧붙이지 않는다. 두 소스의 명시적 할당/IP/비활성 정보가 충돌하면 PASS하지 않는다.

| API (전부 GET) | 확인 내용 / 현재 처리 |
|---|---|
| `/api/firewall/filter/search_rule` | 공식 목록과 controller의 grid 응답 `rows` 확인. 최근 master는 비 MVC/legacy 규칙을 병합하지만 문서에는 Automation 범위 제한 설명도 남아 있다. 버전별 포함 범위, 페이지네이션, alias, 자동/legacy 규칙·적용 순서가 다를 수 있어 전체 정책으로 단정하지 않는다. 현재 수집기는 rows 외형만 검사하고 FW-04는 NEEDS_REVIEW로 남긴다. |
| `/api/firewall/filter/get_rule/{uuid}` | 공식 GET 및 controller의 rule 래퍼 확인. 클라이언트에서 UUID 형식을 검사하고 조회 가능. 기본 실행은 UUID 열거/상세 조회를 수행하지 않는다. OptionField 선택값 등 실제 26.7 상세 응답은 미확인. |
| `/api/interfaces/overview/interfaces_info` | 사용자 확인 dict/rows 외형과 식별 필드를 사용. 기존의 명시적 bool enabled, status=up, ipv4[*].ipaddr=주소/prefix 형태가 실제로 제공되는 경우만 해석하고, 현재 미제공 필드를 생성하지 않는다. |
| `/api/interfaces/overview/export` | 사용자 확인 list 외형을 사용. 원소는 dict인지 검사하고, 상세 필드가 모르면 NEEDS_REVIEW. 합성 테스트의 완전한 명시 필드가 실제 export의 전체 스키마라는 뜻은 아니다. |
| `/api/diagnostics/interface/get_interface_config` | 사용자 확인 403. FW-01 기본 수집에서 제거했다. 별도 진단용 클라이언트 허용 목록에는 남아 있으나 점검은 의존하지 않는다. |
| `/api/diagnostics/firewall/log?limit=20` | 로그 GET에만 limit=20을 명시. controller는 backend 로그 목록을 반환. 공식 `read_log.py`의 `src`, `dst`, `protoname`, `interface`, `action`, `rid`, `__timestamp__`, `__digest__` 확인. 스냅샷 목록/필수 필드를 검사하지만 probe_id/run을 발명하지 않는다. 빈 목록·미확인 구조·현재 시험과 미연결 상태를 구분. |
| `/api/diagnostics/firewall/list_rule_ids` | 사용자 확인 403. 실패는 이 API와 rule_id_mapping에만 기록한다. logs의 수집 성공은 보존한다. 향후 items 응답을 받더라도 실제 연결은 미검증으로 남긴다. |

`stream_log`도 공식 목록에 있으나 지속 연결 대신 제한 시간 있는 `log` GET을 선택했다. timeout, HTTP 실패, TLS/연결 실패, JSON 오류, 401/403을 고정 오류 코드로 처리한다. 오류 응답 본문은 출력하지 않는다.

`api_results`는 각 API의 고정 endpoint, `http_status`, `stage`, 수집 `status`, allowlist된 `error_code`만 보관한다. 401=`api_unauthorized`, 403=`api_forbidden`, 404=`api_not_found`를 구분한다. TLS=`tls/api_tls_failed`, timeout/연결=`transport`, JSON 파싱=`json_parse`, 데이터 구조=`response_schema`로 구별한다. HTTP 200 이후 파싱/구조 실패는 HTTP 200을 보존하고 ERROR 단계만 기록한다. HTTP 응답 전의 TLS/연결 실패는 http_status=null이다. 예외의 기존 짧은 문자열은 호환성을 유지하지만 보고서에는 구분된 코드가 기록된다.

수집 `COLLECTED`는 진단 PASS와 다르다. 로그가 빈 목록이면 `firewall_log_snapshot_empty`, 형식은 알아도 시험과 연결되지 않으면 `current_log_correlation_unverified`이다. rule_id_mapping은 미시도 NOT_TESTED, 조회 실패 ERROR, 조회 성공이어도 실제 연결 검증 전 NEEDS_REVIEW로 별도 보고한다. 규칙 API 403은 FW-04 ERROR와 미검증 scope로 기록하며, 향후 HTTP 200으로 Automation 일부 규칙만 얻어도 전체 coverage를 승인하지 않는다.

`Rule`, `Probe`, `Log`, `Evidence`는 이 프로젝트가 정의한 내부 증거 계약이다. `probe_id`, `execution_id`, `control_ok`, `complete_rules`는 OPNsense API 응답 필드가 아니다. 신규 테스트의 인터페이스 JSON도 공식 소스를 참고해 손으로 만든 합성 데이터다. 테스트용 PASS를 실제 장비 PASS로 보고하지 않는다. CLI에는 합성 데이터를 불러와 실제 결과로 출력하는 옵션이 없다.

실제 로그의 `__timestamp__`는 형식에 따라 연도/시간대가 불완전할 수 있다. digest는 로그 식별 해시이고 실행 ID가 아니다. 현재 실행 ID를 과거 로그에 붙이는 방식은 금지한다. 향후 실제 어댑터는 장비 시간대/시각 동기화, 패킷·시험 식별, 동일 튜플의 동시 트래픽, 로그 지연·회전, rid 매핑을 확인해야 한다.

권한 확인: 공식 Firewall ACL의 `page-filter-api`는 `Firewall: Rules [new]`와 `api/firewall/filter/*`를 묶는다. 이 wildcard는 변경 API까지 포함할 수 있어 그대로 최소 조회 권한이라고 안내하지 않는다. 장비 관리자가 설치 버전의 ACL을 확인하고 위 GET별 권한을 제한해야 한다. 인터페이스·진단 조회는 버전별 권한 매핑을 확인해야 하며, 403 해결을 위해 root/All Pages를 부여하지 않는다. 필요하면 관리자 측의 제한 ACL/접근 제어를 별도로 준비한다. 이 구현은 ACL 설치나 변경을 하지 않는다.

공식 근거:

- [Firewall API](https://docs.opnsense.org/development/api/core/firewall.html)
- [Interfaces API](https://docs.opnsense.org/development/api/core/interfaces.html)
- [Diagnostics API](https://docs.opnsense.org/development/api/core/diagnostics.html)
- [API 계정·키와 CA 사용](https://docs.opnsense.org/development/how-tos/api.html)
- [FilterController](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterController.php)
- [OverviewController](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Interfaces/Api/OverviewController.php)
- [InterfaceController](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Diagnostics/Api/InterfaceController.php)
- [FirewallController](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Diagnostics/Api/FirewallController.php)
- [로그 backend](https://github.com/opnsense/core/blob/master/src/opnsense/scripts/filter/read_log.py)
- [Firewall ACL](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/Firewall/ACL/ACL.xml)

## D. 신규 테스트

`.\.venv\Scripts\python.exe -B -m unittest tests.test_opnsense_log_rule_evidence tests.test_opnsense_pf_evidence tests.test_opnsense_lab_audit tests.test_opnsense_manual_evidence -v`: **162개 전부 통과** (기존 139개 유지 + FW-05 로그 연계 23개).

LAN/WAN IP·마스크·할당·활성 상태, 누락/중복, WAN과 LAN 관리 접속 구분, 허용/차단/불명 시험, Quick·순서·shadowing, 비활성 규칙, host ICMP 예외 범위, 로그 양쪽 action 및 튜플/rid/시간/run 불일치, Ping 미실행, 인증/ACL/TLS/JSON/HTTP 오류, 목적지·경로 주입 차단, CA 필수, 리디렉션/환경 프록시 차단, 안전한 출력, 실제 evaluate() 6회 호출 등을 확인했다.

신규 테스트는 HTTP 세션/Ping 프로세스를 mock하며 Docker·Hyper-V·OPNsense가 필요 없다.

보완 항목: export list/overview rows, 확인된 필드만 있는 부분 응답, config/flags 미해석, 누락/중복/잘못된 원소, 한 소스 실패 시 다른 소스 활용, 소스 간 충돌, 부분 403, 로그만 200, 빈 로그, ID 조회와 로그 오류 분리, 규칙 200의 coverage 미승인, HTTP/TLS/timeout/파싱 단계별 메타데이터 및 비밀 비출력을 확인했다. 모든 fixture 값은 합성이며 실제 장비 응답 파일을 저장하지 않았다.

로그 보완 9개는 limit=20 및 CA 유지, 다른 API 인자 불변, 원본 IncompleteRead, requests ChunkedEncodingError, 중첩된 IncompleteRead, HTTP 200 후 읽기 실패, 실제 JSON 파서의 잘린 본문 거부, 정상 로그+ID 매핑 403+FW-01 PASS 유지, 로그 잘림+ID 매핑 403의 오류 독립성을 확인한다. API Key/Secret/Authorization/partial log가 보고서에 나오지 않는 것도 검사한다.

## E. 전체 회귀 테스트

저장소 CI와 같은 검색 패턴으로 전체 실행:

`python -B -m unittest discover -s tests -p "test_*.py"`

2026-11-06 FW-05 로그 연계 추가 후 결과: **543개 실행, 542개 통과, 기존 테스트 1개 실패**. Day4 162개는 전부 통과했고 기존 381개 중 380개가 통과했다. 따라서 전체 통과라고 보고하지 않는다. 프레임워크는 저장소 CI와 동일한 unittest이며 pytest 설치는 필요 없다.

실패: `test_ec2_owner_deployment_script_syntax`. Git Bash가 Windows 샌드박스에서 `NtCreateDirectoryObject(\BaseNamedObjects\msys-...)`를 생성하지 못해 `0xC0000022`, 반환 코드 3221225794로 종료했다. Day 4 로직 실패가 아닌 실행 환경 제한이다. 테스트 삭제·수정·skip이나 결과 조작은 하지 않았다. 권한이 있는 일반 Windows PowerShell에서 재실행할 필요가 있다.

최초 실행에서는 sandbox 임시 폴더 쓰기 제한과 localhost 소켓 제한도 관찰되어, 쓰기 가능한 TEMP/TMP 지정 및 localhost 테스트용 네트워크 권한으로 해결했다. WindowsApps의 bash stub 대신 설치된 Git Bash를 PATH 앞에 지정했지만 커널 객체 생성 제한은 남았다. `git diff --check`도 통과했다.

## F. 아직 실제 검증하지 못한 부분

- 제한된 로그 GET의 정상 수신은 사용자의 장비 검증 결과이며, 이번 수정 후 실행기를 실제 장비에서 재실행하지 않았다. 운영 환경에서 limit=20의 지속적인 정상 수신, FW-01 PASS 유지, FW-05 수집 COLLECTED와 ID 매핑 403의 독립 기록을 재확인해야 한다. 최신 20건에 필요한 이벤트가 없더라도 정책 미작동으로 단정하지 않는다.
- 사용자가 보고한 API 접근 상태와 구조만 반영했다. 이 세션에서는 API 인증·인증서·실제 인터페이스·적용 정책·실제 로그·Ping을 독립적으로 재검증하지 않았다. 현재 VM 전원 상태는 확인하지 않았다.
- overview/export의 config·flags·실제 IP 및 활성 필드의 상세 구조/값이 아직 미제공이다. 현재 확인된 정보만으로 FW-01 PASS를 보장할 수 없고 NEEDS_REVIEW가 정상이다.
- 실제 `--execute`는 API 조회의 틀과 FW-01 어댑터를 제공한다. 전체 유효 ruleset을 정규화하는 실제 어댑터는 아직 없으므로 FW-04는 조회 성공만으로 PASS하지 않는다.
- 로그 필드/외형은 검사하지만 현재 시험과의 확실한 연결 및 rule ID 매핑이 미검증이므로 FW-05/06 실환경 PASS는 아직 확정할 수 없다. `--execute --ping`도 Ping 성공만으로 PASS하지 않는다.
- FW-02/03의 WAN 측 증거는 Windows LAN 실행으로 만들 수 없다. 현재 CLI는 WAN 시험을 자동 수행하지 않으며 향후 승인된 WAN 측 수집 경로가 필요하다. 증거가 없으면 NOT_TESTED이다.
- 차단 Ping의 timeout은 장비/Alpine 장애와 구분해야 한다. 정상 대조와 차단 로그가 없으면 차단 PASS가 아니다. ICMP DestinationHostUnreachable 등은 inconclusive로 처리한다.
- 암호화된 OPNsense XML 백업은 읽지 않으며 평문 XML로 해석하지 않는다. 원본 백업을 로그나 저장소에 복사하지 않는다.

## G. Windows PowerShell 실행

기본 준비 모드: 네트워크와 Ping을 실행하지 않는다.

```powershell
Set-Location 'C:\Projects\infrastructure-security-scanner-clone'
$env:PYTHONIOENCODING = 'utf-8'
python -B -m scripts.run_opnsense_lab_audit
```

프로젝트 의존성이 `.venv`에만 설치되어 있다면 `python` 대신 `.\.venv\Scripts\python.exe`를 사용한다.

오프라인 테스트:

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_opnsense_lab_audit -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py'
```

향후 운영자가 준비를 완료하고 명시적으로 실행할 때만:

```powershell
# Key/Secret은 비밀 저장소 등에서 현재 프로세스 환경으로 주입한다.
# 실제 비밀을 명령행 리터럴, 파일, PowerShell 기록이나 Git에 적지 않는다.
$env:OPNSENSE_API_ACCOUNT = 'audit-reader'
$env:OPNSENSE_CA_BUNDLE = 'C:\secure\opnsense-lab-ca.pem'
python -B -m scripts.run_opnsense_lab_audit --execute

# 현재 비활성 Block 상태에 맞는 pass 시나리오
python -B -m scripts.run_opnsense_lab_audit --execute --ping --scenario pass

# 운영자가 별도로 Block 정책을 준비한 실습에서만 사용
python -B -m scripts.run_opnsense_lab_audit --execute --ping --scenario block
```

필수 환경 변수는 `OPNSENSE_API_ACCOUNT`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`, `OPNSENSE_CA_BUNDLE`이다. 이 문서의 향후 실행 명령은 이번 개발 과정에서 실행하지 않았다.

`--execute` 없이 `--ping`을 주면 오류로 종료한다. Ping은 고정 PowerShell 스크립트가 `Find-NetRoute`로 선택 출발지가 `10.77.40.10`인지 확인한 후 한 번의 .NET Ping을 전송한다. 목적지는 `10.77.50.10`으로 고정된다. 이 ICMP는 API 목적지 예외이며 별도 `--ping` 승인이 필요하다. API 클라이언트의 목적지는 항상 `https://10.77.40.1`이다.

## H. 실제 연결 전 준비

1. 운영자가 VM 및 네트워크를 준비한다. 도구는 VM을 시작·종료·수정하지 않는다. Windows LAN 주소와 경로, OPNsense hn0/hn1 할당을 확인한다.
2. Alpine Live 환경은 재부팅마다 `10.77.50.10/24`, gateway `10.77.50.1`을 별도로 복원한다. Alpine과 경로 정상 상태를 대조 시험으로 확인한다.
3. root가 아닌 전용 계정을 생성하고 설치된 26.7의 조회별 ACL을 검증한다. API key의 실제 소유자가 해당 비 root 계정인지 운영자가 확인해야 한다. 환경 변수의 account 이름 검사는 키 소유자를 서버에서 증명하는 기능이 아니다.
4. HTTPS 인증서의 체인과 `10.77.40.1` IP SAN을 검증하고 CA PEM을 명시적으로 신뢰한다. 이 구현은 CA 검증 방식을 사용하며 certificate pin 방식은 구현하지 않았다. `verify=False`나 TLS 전역 비활성화는 없다.
5. 비밀 저장소에서 Key/Secret을 환경 변수로 공급한다. 코드·Git·로그·원본 백업에 비밀을 넣지 않는다. 클라이언트는 환경 프록시와 netrc를 사용하지 않고 리디렉션도 따라가지 않는다.
6. 실제 응답을 안전한 장소에서 검토하여 버전별 필드, 규칙 조회 범위/페이지네이션, 전체 적용 순서, rid와 UUID/legacy ID 매핑을 확인한다. 이 확인 후에만 실제 정규화 어댑터의 coverage를 승인한다.
7. 시간 동기화와 방화벽 허용/차단 로깅을 별도 준비하고, WAN 측 443·승인 ICMP·비인가 TCP 시험 및 현재 실행의 식별 가능한 로그를 수집할 경로를 준비한다.
8. 현재 Block은 비활성이므로 기본 pass 시나리오를 선택한다. block 시나리오 선택은 정책을 변경하지 않는다. 규칙 추가·수정·삭제·toggle, apply/restart, 상태 테이블 초기화 API는 클라이언트 허용 목록에 없다.

## I. 선택적 수동 증적 연계

이번 작업에서는 `config_audit/manual_evidence.py`, `examples/opnsense-manual-evidence.template.json`, `tests/test_opnsense_manual_evidence.py`를 추가하고 실행 스크립트와 본 문서를 수정했다. OPNsense 수집기 및 FW-01~06 자동 판정 함수는 변경하지 않았다. FW-01 자동 PASS, 로그 GET limit=20, 로그 수집과 ID 매핑 403의 분리는 유지한다.

초기 구현 당시에는 실제 화면·시험 파일이 없어 빈 템플릿만 제공했다. 이후 로컬 `evidence/day4/screenshots/`의 PNG 7개 및 기존 `fw06-ping-allow.txt`를 직접 확인하고, 실제 `evidence/day4/manual.json`을 수정했다. 템플릿은 계속 미작성 상태를 유지한다. 실제 등록 상태는 아래 J절과 같다.

### 저장 위치와 기본 실행

실제 수동 JSON과 비식별화한 첨부 파일은 기존 `.gitignore`가 제외하는 `evidence/day4/`에 둔다. 프로그램은 이 디렉터리에 파일을 생성하거나 복사하지 않는다. 사용자가 파일을 준비한 뒤 다음처럼 템플릿을 복사한다.

```powershell
Set-Location 'C:\Projects\infrastructure-security-scanner-clone'
New-Item -ItemType Directory -Force '.\evidence\day4' | Out-Null
Copy-Item '.\examples\opnsense-manual-evidence.template.json' '.\evidence\day4\manual.json'
# 직접 비식별화한 화면/시험 결과 파일을 evidence/day4/ 아래에 배치한다.
# 다음 값은 해당 sources 항목의 sha256에 소문자로 입력한다.
(Get-FileHash '.\evidence\day4\sanitized-test.txt' -Algorithm SHA256).Hash.ToLowerInvariant()

# 오프라인: 수동 파일 검사·첨부만 수행, API/Ping 실행 없음
python -B -m scripts.run_opnsense_lab_audit --manual-evidence '.\evidence\day4\manual.json'

# 운영자가 별도로 승인하여 API 조회도 실행할 때만
python -B -m scripts.run_opnsense_lab_audit --execute --manual-evidence '.\evidence\day4\manual.json'
```

과거 FW-06의 수동 Ping 증거를 첨부하는 데 `--ping`은 필요 없다. `--ping`은 새 Ping을 실행하는 별도 승인 옵션이며 과거 수동 시험을 현재 자동 증거로 바꾸지 않는다. 이번 작업에서 위 실제 장비 실행 명령은 수행하지 않았다.

### JSON 작성 규칙

최상위 필수 키는 `schema_version: 1`, `asset_id: "SJ-D4-OPNsense"`, `checks` 배열이다. 한 check_id당 최대 한 항목이며 최대 6개다. 필요 없는 템플릿 항목은 삭제하거나 초안 NOT_TESTED로 유지한다. 초안은 verified_at=null, sources/tests=[]이어야 한다.

완료한 수동 항목에는 다음을 입력한다.

- `check_id`: FW-01~06. 자동 FW-01이 충분하면 수동 FW-01을 넣지 않아도 된다.
- `reported_status`: 운영자 주장 PASS / FAIL / NEEDS_REVIEW / NOT_TESTED.
- `verified_at`: 실제 수동 시험 시각. 예시 형식 `2026-11-06T14:00:00+09:00`처럼 시간대를 포함하고 미래 시각을 사용하지 않는다. 예시 시각을 실제 시험 시각으로 간주하지 않는다.
- `time_basis`: 선택 항목으로 기본값은 test_time. 원래 시험 시각/시간대가 확인되지 않을 때는 artifact_review로 지정하고 verified_at에 실제 파일 검토·등록 시각을 넣는다. 이 시각은 원래 트래픽 시험 시각이 아니다. 허용되지 않은 time_basis 값은 거부한다.
- `scope`: 아래 표의 고정 문자열. 임의의 광범위한 보증 문구를 넣지 않는다.
- `sources`: 실제 첨부 파일의 `kind`, JSON 디렉터리 기준 상대 `path`, 파일 바이트의 소문자 SHA-256 `sha256`.
- `tests`: FW-02/03/06의 출발지·목적지·프로토콜·포트·기대/실제 결과·로그 Action·규칙명·출처 연결을 담는 배열.
- `inspection`: FW-04 완료 항목에서만 사용하는 화면 관찰 객체.

| check_id | scope 및 한계 |
|---|---|
| FW-01 | `interface_assignment_only` |
| FW-02 | `wan_to_firewall_tcp443_only`: Alpine WAN → 방화벽 WAN TCP/443. LAN 관리 접속은 별도 대조 항목으로 기록 가능 |
| FW-03 | `wan_to_firewall_tcp22_only`: Alpine WAN → 방화벽 WAN TCP/22만. WAN→LAN 내부 서버 전달, 승인 ICMP 또는 전체 인바운드 정책을 검증했다는 뜻이 아님 |
| FW-04 | `rules_inspect_screen_only`: Inspect 화면 관찰만. 규칙 전체 적용 정책·API 권한·자동 분석 완료와 구분 |
| FW-05 | `log_collection_only`: 로그 수집 확인만. 실제 패킷/규칙의 자동 연결과 구분 |
| FW-06 | `windows_to_alpine_icmp_lab_only`: 지정된 Windows→Alpine 실습 경로와 시나리오만 |

`sources.kind`는 screenshot / test_output / firewall_log / inspect_view / operator_note 중 하나다. operator_note는 운영자 진술 파일이며, 원본 화면·패킷 증거와 동일하게 입증된 것으로 해석하면 안 된다. 프로그램은 첨부 내용의 사실 여부를 판독하지 않는다. 인증 정보·개인키·Authorization 헤더·불필요한 민감 로그를 첨부에 넣지 말고 사전에 비식별화한다. 원문은 출력/복사/저장하지 않고 읽어서 해시만 대조한다.

완료한 tests 원소의 형식 예시는 아래와 같다. 이는 작성 형식 안내이며 이번 작업에서 첨부된 실제 시험 기록이 아니다. sources[0]과 sources[1]에 해당하는 실제 파일, SHA-256, 실제 시각을 먼저 입력해야 한다.

```json
{
  "scenario": "block",
  "source": "10.77.50.10",
  "destination": "10.77.50.1",
  "protocol": "tcp",
  "port": 443,
  "expected_result": "blocked",
  "actual_result": "timeout",
  "firewall_action": "block",
  "rule_name": "Default deny / state violation rule",
  "source_indices": [0, 1]
}
```

`source_indices`는 sources 배열의 0부터 시작하는 인덱스이며 없는 출처를 참조할 수 없다. 실제 결과는 success / timeout / unreachable / inconclusive, firewall_action은 pass / block / reject / not_observed 중 하나다. `rule_name`은 null 또는 이번 실습의 `Default deny / state violation rule`, `LAB-D4-Block-Windows-Alpine`, `anti-lockout`, `LAN default allow`만 허용한다. 자유 메모·임의 규칙명·추가 필드는 받아서 출력하지 않는다. 다른 규칙명이나 대상 범위가 필요하면 계약을 검토해 확장해야 한다.

FW-03은 위 형식에서 port=22만 허용한다. FW-02의 LAN 대조 시험은 `10.77.40.10 → 10.77.40.1`, tcp/443, scenario=pass, expected_result=allowed, actual_result=success로 별도 원소를 기록할 수 있다. LAN 성공만으로 WAN 차단 PASS를 만들 수 없다. WAN 차단 PASS 주장에는 timeout과 block/reject 및 기본 차단 규칙명이 모두 필요하다.

FW-06은 `10.77.40.10 → 10.77.50.10`, protocol=icmp, port=null이며 tests에 다음 세 시나리오를 기록한다. 각 원소에 실제 출처 인덱스를 연결한다.

| scenario | 기대/실제 | 추가 필드 |
|---|---|---|
| pass | allowed / success | packets_sent=4, packets_received=4, 로그 미수집이면 firewall_action=not_observed, rule_name=null |
| block | blocked / timeout | packets_sent=4, packets_received=0, firewall_action=block, rule_name=LAB-D4-Block-Windows-Alpine |
| restored | allowed / success | packets_sent=4, packets_received=4, 로그 미수집이면 not_observed/null |

이 값들은 사용자가 실제 수행한 시험 증거와 일치할 때만 입력한다. 블록 규칙을 켜거나 끄는 자동 기능은 없다. restored가 빠졌거나 PASS 주장과 실제 결과가 내부적으로 모순이면 수동 상태도 PASS로 인정하지 않는다.

FW-04는 tests=[]로 두고 `inspection`에 다음 필수 키를 입력한다. `rule_count`는 실제 화면의 정수 개수(사용자 보고 18), `default_deny_seen`, `anti_lockout_seen`, `lan_default_allow_seen`, `lab_block_before_default_allow`, `lab_block_enabled`는 bool이다. 사용자가 보고한 현재 비활성 상태는 lab_block_enabled=false에 해당한다. 이 객체도 실제 Inspect 증거 파일과 연결해야 한다. 수동 화면 확인 PASS를 입력하더라도 자동 FW-04의 API 403/ERROR를 덮어쓰지 않는다.

### 결과 해석과 오류 처리

기존 `results[*].status`는 계속 자동 판정이다. `automatic_status`는 같은 자동 상태를 명시하고 `manual_verification`에 운영자 주장과 검증 범위를 분리한다.

- 수동 `reported_status`: 운영자의 원래 주장. 자동 판정과 다르다.
- 수동 `status`: 파일 무결성/필수 증거/주장의 내부 일관성을 검사한 결과. 자료가 부족하면 원래 PASS 주장을 유지해 보여 주되 status는 NEEDS_REVIEW로 낮춘다.
- `validation_status`: DRAFT / VALID / INCOMPLETE. VALID는 구조와 파일 해시 일치만 의미하며 내용의 진실성을 자동 검증했다는 뜻이 아니다.
- `attached`: 실제 파일을 모두 읽고 해시가 일치한 경우만 true. 원본 경로/내용 대신 불투명한 source 참조와 파일 종류·무결성 결과만 출력한다.
- `content_verified_by_agent=false`, `current_execution_evidence=false`: 수동 진술·과거 파일을 이번 자동 실행의 시험으로 간주하지 않는다.
- `comparison`: 자동/수동 PASS와 FAIL이 반대이면 `STATUS_CONFLICT_REQUIRES_REVIEW`. 원인은 시각·범위·정책 변경일 수도 있으므로 어느 쪽을 자동으로 덮어쓰지 않는다. 자동 ERROR/NOT_TESTED와 수동 PASS는 별도 범위·시각의 결과로 보존한다.

파일이 없으면 첨부됐다고 표시하지 않는다. JSON 문법/타입/알 수 없는 필드/중복 키·항목/잘못된 대상/출처 인덱스/시각 오류는 고정된 안전 오류 코드로 반환한다. 구조가 잘못된 manual 파일을 지정한 `--execute`는 API/Ping 전에 중단하고 execution_skipped=true로 기록한다. 정상 JSON이지만 파일 누락·해시 불일치이면 수동 항목은 INCOMPLETE/NEEDS_REVIEW로 남고, 명시적으로 승인된 자동 수집은 독립적으로 수행할 수 있다.

실제 source 경로는 JSON 디렉터리 내부 상대 경로만 허용한다. 절대 경로·상위 이동·외부로 향하는 링크는 거부한다. JSON 최대 128KiB, 첨부 파일 하나 최대 16MiB, 항목별 출처/시험 최대 20개다. source 파일의 민감 본문·예외 메시지·JSON 경로를 보고서에 출력하지 않는다. 코드는 실제 수동 증거 파일을 생성하지 않는다.

자동 FAIL/ERROR, 수동 FAIL, 수동 파일 오류/자료 부족, 자동·수동 상태 충돌이 있으면 종료 코드 1이다. 미작성 템플릿이나 수동 파일 미지정은 자동 결과가 정상 준비 상태인 경우 종료 코드 0이며 진단 PASS를 뜻하지 않는다.

수동 연계 26개 테스트는 파일 미지정/미존재, 빈 템플릿, 증거 누락/해시 불일치/크기·경로 제한, 잘못된 JSON/필드/시각/대상, 비밀 비출력, PASS/Block/복구 시나리오, 범위 제한, 자동 상태 충돌, FW-01 PASS 및 FW-05 COLLECTED 보존, 준비 모드 무통신, 잘못된 증거 파일의 실행 차단, 파일 검토 시각과 시험 시각 구분을 검증한다.

## J. 실제 로컬 manual.json 최초 등록 결과 (후속 복구 증적 추가 전)

`C:\Projects\infrastructure-security-scanner-clone\evidence\day4\manual.json`을 직접 갱신했다. 원본 PNG 7개와 기존 허용 전사본 TXT 1개는 수정하지 않았다. 새 `evidence/day4/registration-source-notes.txt`에는 이번 대화에서 보고된 사실, 전사본의 출처, 증거의 한계만 명시했다. 이 노트는 원본 API 응답이나 독립된 시험 출력이 아니다.

스크린샷에서 FW-02/03의 TCP Timeout 및 WAN 방화벽 주소 대상 기본 차단 로그, FW-04의 18개 규칙·상위의 비활성 실습 Block, FW-06의 ICMP Block과 Ping 4개 중 0개 수신을 확인했다. 원래 시험의 시간대와 복구 후 패킷 수를 확인할 수 없어 새로 만들지 않았다. 각 record는 time_basis=artifact_review를 명시하고 실제 검토·등록 시각을 사용한다.

| 항목 | 수동 status | validation_status | attached | 등록 범위/한계 |
|---|---|---|---|---|
| FW-02 | PASS | VALID | true | WAN 10.77.50.10 → 10.77.50.1 TCP/443 Timeout + Default deny block; PNG 2개 |
| FW-03 | PASS | VALID | true | 같은 WAN 경로 TCP/22 Timeout + Default deny block; PNG 2개. LAN 내부 서버 전달은 범위 밖 |
| FW-04 | NEEDS_REVIEW | VALID | true | Inspect PNG의 18개 규칙 및 비활성 실습 Block 위치만. 전체 적용 정책/API 접근을 검증한 것이 아님 |
| FW-05 | NEEDS_REVIEW | VALID | true | 대화의 API HTTP 200/COLLECTED 및 ID 조회 403 진술을 operator_note로 보존. 실제 API 응답 파일은 미제공이고 현재 세션에서 API 미조회 |
| FW-06 | NEEDS_REVIEW | INCOMPLETE | true | reported_status=PASS는 사용자 주장을 보존. 허용 4/4는 기존 대화 출력 전사본, 차단 0/4와 규칙 로그는 PNG. 복구 후 정확한 시험 자료 누락으로 manual_restore_test_missing |

모든 실제 출처는 9개 고유 파일(원본 PNG 7 + 기존 TXT 1 + 출처 노트 1)이며 총 13개 참조의 존재·상대 경로·SHA-256을 실제 파일 바이트로 재계산하여 모두 MATCH를 확인했다. 해시는 manual.json 안에 저장되어 있다. 5개 등록 항목에 DRAFT는 남지 않는다. FW-01은 수동 항목을 만들지 않았으며 기존 자동 기능을 유지한다.

실제 파일 실행 검증:

```powershell
Set-Location 'C:\Projects\infrastructure-security-scanner-clone'
.\.venv\Scripts\python.exe -B -m scripts.run_opnsense_lab_audit --manual-evidence '.\evidence\day4\manual.json'
```

manual_evidence=LOADED이며 위 표와 일치한다. 종료 코드 1은 JSON 로드 실패가 아니라 FW-06 수동 증적 INCOMPLETE 때문이다. restored 시나리오를 채우기 위해 확인되지 않은 4/4 결과를 만들지 않았다. 이번 실행은 --execute 없는 오프라인 검증이므로 자동 상태는 NOT_TESTED이고, 기존 실장비 FW-01 PASS나 FW-04 API 403을 새로 측정했다고 주장하지 않는다. 수집기·자동 판정·API 권한·방화벽 설정은 변경하지 않았다.

등록된 FW-06 허용 파일은 스크린샷이 아니라 대화 출력 전사본임을 sources.kind=operator_note 및 출처 노트에 명시했다. 사용자가 확인한 합계 4/4만 활용하며 파일 안의 개별 응답행·TTL·지연값을 별도로 검증했다고 주장하지 않는다. 복구 확인은 사용자의 정성적 진술로 보존하고 수치화하지 않았다.

## K. FW-06 후속 복구 증적 등록 완료

후속 실제 파일 `evidence/day4/fw06-restore-ping.txt`를 직접 확인했다. 원본에는 `CapturedAt: 2026-11-06T01:56:29.4652546+09:00`, `ping -n 4 10.77.50.10`, 전송 4/수신 4/손실 0%, TTL=63 응답 4개가 기록되어 있다. 파일 바이트의 SHA-256은 `6c2708b0023eb9551761fd61ef0a266238d65bb80c649229c670ed83b90eb2bd`이다.

실제 `evidence/day4/manual.json`의 FW-06 sources에 원본을 test_output으로 추가하고 restored 시나리오(4/4 성공)를 연결했다. `fw06-restore-followup-notes.txt`에는 원본 CapturedAt, 이전 검토 시각, 이번 완료 검토 시각을 구분하여 기록했다. 최초 허용 시험이 대화 전사본이라는 한계는 유지하며 새 복구 파일로 이를 대체하지 않았다. 과거 등록 노트의 복구 증거 부족 설명은 당시 상태이고, 새 후속 노트가 해당 부족분의 해소를 설명한다.

FW-06 verified_at은 이번 실제 완료 검토 시각 `2026-11-05T16:59:06.806166+00:00`으로 갱신하되 time_basis=artifact_review를 유지했다. 이는 한국 시각 2026-11-06 01:59:06의 자료 검토이며, 원본 복구 시험 CapturedAt과 다르다. 기존 시각은 과거 노트와 후속 노트에 보존했다. 기존 스크린샷·허용 전사본·등록 출처 노트의 파일 내용/해시, FW-06의 기존 sources/tests, FW-02~05 JSON 항목은 변경하지 않았다.

| 항목 | 기존 실장비 자동 상태(재측정 아님) | 현재 수동 상태 | 수동 증적 유효성 |
|---|---|---|---|
| FW-01 | PASS | 미등록/NOT_TESTED | 자동 기능 유지 |
| FW-02 | NOT_TESTED | PASS | VALID / attached=true |
| FW-03 | NOT_TESTED | PASS | VALID / attached=true, WAN 방화벽 TCP/22만 |
| FW-04 | ERROR (규칙 API 403) | NEEDS_REVIEW | VALID / attached=true, Inspect 화면 범위만 |
| FW-05 | NEEDS_REVIEW (로그 COLLECTED, ID 조회 403) | NEEDS_REVIEW | VALID / attached=true, 기존 사용자 진술 출처 유지 |
| FW-06 | NOT_TESTED | PASS | VALID / attached=true, 허용·차단·후속 복구 충족 |

위 자동 열은 이전 실장비 결과와 미실행 항목을 요약한 것으로, 이번 작업에서 자동 PASS/ERROR를 새로 측정했다는 뜻이 아니다. 이번 실제 CLI 검증은 --execute 없는 오프라인 실행이므로 생성된 실행 JSON의 자동 상태는 모두 NOT_TESTED다. 기존 자동 결과를 수동 PASS로 덮어쓰지 않는다.

총 11개 고유 파일, 15개 출처 참조의 파일 존재·상대 경로·SHA-256을 다시 계산해 모두 MATCH를 확인했다. 실제 manual.json을 읽은 실행에서 manual_evidence=LOADED, FW-06=PASS/VALID/attached=true이며 종료 코드 0이다. DRAFT 및 INCOMPLETE가 등록 항목에 남아 있지 않다. 코드/템플릿/기존 테스트를 바꾸지 않고 실제 증적과 문서만 보완했다.

Day4 unittest 114개는 모두 통과했다. 전체 unittest 495개 중 494개가 통과했고, 기존 `test_ec2_owner_deployment_script_syntax` 1개는 Git Bash의 NtCreateDirectoryObject 권한 오류(0xC0000022)로 실패했다. 테스트를 삭제·수정·skip하지 않았다. 실제 방화벽 API 호출·설정 변경·계정 권한 변경·Git commit은 수행하지 않았다.

## L. FW-04 PF 스냅샷 분석 확장

`config_audit/collectors/opnsense_pf.py`, `tests/test_opnsense_pf_evidence.py`, `docs/opnsense-pf-snapshots.md`를 추가하고 CLI와 문서를 수정했다. --pf-rules-evidence로 파일만 읽는 오프라인 분석을 선택할 수 있다. 기존 API 상태/403과 수동 상태는 그대로 두고 FW-04의 별도 pf_snapshot에 기존 evaluate()를 이용한 상태를 출력한다.

실제 tar 해시와 member 바이트, 일반/상세 64개 필터 규칙의 순서가 일치했다. 기본 차단·LAN 기본 IPv4 허용·LAN HTTP/HTTPS·WAN 지정 ICMP 구조는 확인했지만 동적 테이블/주소 및 전체 적용 범위가 미검증이므로 실제 PF 결과는 NEEDS_REVIEW다. GUI 실습 Block 비활성 상태와 전체 정책 안전성을 자동 PASS로 만들지 않았다. 명령·상세 범위·무결성 값·필요한 읽기 전용 후속 수집은 `docs/opnsense-pf-snapshots.md`에 기록했다. 원본 PF 증적/수동 JSON, 기존 자동 판정, 방화벽 및 API 권한은 변경하지 않았다.

## M. FW-05 저장 로그와 실제 규칙 연결

`config_audit/collectors/opnsense_log_rules.py`, `tests/test_opnsense_log_rule_evidence.py`, `docs/opnsense-log-rule-evidence.md`를 추가하고 CLI/문서를 수정했다. --fw05-log-evidence와 SHA-256, 시험 구간 및 PF 입력으로 파일만 분석한다. live 로그 API/ID 매핑과 로컬 수집/규칙 연결/증적 판정을 분리하며 기존 자동·수동 상태를 덮어쓰지 않는다.

실제 fw05-wan-tcp22.json의 3건은 튜플·block·RID/PF label·상세 @6·벽시계 범위가 일치했다. 단순 rulenr 일치보다 강한 연결 후보이나 로그 timezone 및 시험 시점의 규칙 세대 연속성이 미입증이라 최종 NEEDS_REVIEW다. 이번에 API는 실행하지 않았으며 기존 limit=20, IncompleteRead 및 403 분리는 유지한다. 정확한 실행 명령/부족 조건/context 계약과 검사 결과는 전용 문서에 기록했다. 원본 실제 증적은 수정하거나 Git에 넣지 않았다.
