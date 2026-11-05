# FW-04 — PF 적용 규칙 스냅샷 오프라인 분석

대상: `C:\Projects\infrastructure-security-scanner-clone`, `feature/day4-opnsense`. 작성일: 2026-11-06, Asia/Seoul.

## 구현과 결과 분리

`config_audit/collectors/opnsense_pf.py`가 파일만 읽어 PF 규칙을 분석한다. 외부 명령·SSH·API를 실행하지 않는다. `scripts/run_day4_audit.py`의 선택 옵션으로 연결했으며, 상태 판정은 기존 `config_audit.engine.evaluate()`를 사용한다. 기존 OPNsense API 수집기, FW-01~06 자동 판정 및 수동 증적 검증기는 변경하지 않았다.

FW-04의 기존 `status`, `automatic_status`, `api_results`, `manual_verification`은 유지하고, 별도 `pf_snapshot`에 스냅샷 분석 결과를 기록한다. API 403이 발생한 실행에서 스냅샷이 제한 범위 PASS여도 기존 자동 ERROR와 HTTP 403은 지워지지 않는다. 수동 PASS 역시 자동 결과를 대체하지 않는다.

이번 실제 검증은 --execute 없는 오프라인 실행이다. 따라서 이번 실행의 기존 자동 상태는 NOT_TESTED이며, 알려진 과거 규칙 API 403을 새로 조회했다고 주장하지 않는다. API 수집과 PF 분석의 오류/상태를 구분하는 동작은 Mock 통합 테스트로 검증했다.

## 실행 명령

사용자가 제공한 독립적인 archive SHA-256을 기준으로 실제 두 파일을 검증하는 권장 명령:

```powershell
Set-Location 'C:\Projects\infrastructure-security-scanner-clone'
.\.venv\Scripts\python.exe -B -m scripts.run_day4_audit `
  --pf-rules-evidence '.\evidence\day4\fw04-active-rules.txt' `
  --pf-rules-detail '.\evidence\day4\fw04-active-rules-detail.txt' `
  --pf-rules-archive '.\evidence\day4\fw04-rules.tar' `
  --pf-rules-archive-sha256 B0CA18A9DE3C701C5B7E63CEC45443C7B544C8DED2D44595F644463837FCB8AF
```

기존 수동 증적도 함께 표시하려면 `--manual-evidence '.\evidence\day4\manual.json'`을 추가한다. 이번 실제 실행은 이 옵션도 함께 사용했으며 FW-02/03/06 수동 PASS 및 FW-04/05 수동 NEEDS_REVIEW를 유지했다. manual.json이나 원본 증적 파일을 수정하지 않았다.

파일 하나만 분석할 수도 있다.

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_day4_audit `
  --pf-rules-evidence '.\evidence\day4\fw04-active-rules.txt' `
  --pf-rules-sha256 6efaac2b285f0b677da6d018eedf40b598814eba7d11dc6c50504979d3d7719a
```

이 예시의 해시는 이번에 확인한 파일의 값이다. 다른 수집본에는 독립적으로 확보한 기대 해시를 사용한다. 입력 파일에서 그때그때 계산한 값을 같은 실행의 기대 해시로 넣는 것만으로 출처·변조 방지 신뢰가 생기지는 않는다.

옵션은 `--pf-rules-evidence`, 선택적 `--pf-rules-detail`, 각각의 `--pf-rules-sha256` / `--pf-rules-detail-sha256`, 선택적 `--pf-rules-archive` / `--pf-rules-archive-sha256`이다. 기대 해시가 없으면 파싱은 하지만 NEEDS_REVIEW이며 파일 존재만으로 PASS하지 않는다. archive 해시가 일치하면 필요한 member 바이트가 실제 입력 파일과 같은지도 검사한다. tar는 파일시스템에 추출하지 않고 읽으며, 중복 member·상위 경로·링크·크기 초과를 거부한다.

--execute를 추가한 경우에만 기존 조회 전용 HTTPS API도 실행한다. PF 입력 오류/해시 불일치는 네트워크 요청 전에 검출하고 execution_skipped=true로 기록한다. NEEDS_REVIEW는 분석 명령의 실패를 뜻하지 않으므로 다른 ERROR/FAIL이 없으면 종료 코드 0이다. 0을 전체 정책 PASS로 해석하면 안 된다.

## 실제 파일 무결성

| 파일 | 바이트 | SHA-256 |
|---|---:|---|
| fw04-active-rules.txt | 7,667 | 6efaac2b285f0b677da6d018eedf40b598814eba7d11dc6c50504979d3d7719a |
| fw04-active-rules-detail.txt | 23,059 | dd3da77ccfb1cceb98631205800f01cbe20ce347e99b4ca6e935ead0a8bdb495 |
| fw04-rules.tar | 33,280 | b0ca18a9de3c701c5b7e63cec45443c7b544c8ded2d44595f644463837fcb8af |

archive 해시는 사용자 제공값과 일치했다. 압축 내부 두 member의 실제 바이트가 외부 입력 파일과 일치했다. -sr와 -vvsr를 비교할 때 상세 출력의 @번호/카운터 행 및 동적 참조의 표시용 개수 suffix를 구분했다. 동적 참조의 개수는 실제 주소/테이블 내용으로 취급하지 않았다. 필터 규칙 64개의 순서·내용이 일치했고 scrub 행은 별도 정규화 문장으로 처리했다. 상세 출력의 카운터 및 Last Active Time은 현재 실행의 트래픽·수집 시각으로 사용하지 않았다.

해시 일치는 수집 당시의 전체성·정책 안전성·발급자 서명을 증명하는 것이 아니다. 두 파일이 독립된 시각에 수집됐을 가능성도 있으므로 이 분석은 동일한 규칙 문장 집합의 스냅샷 비교이며 원자적 수집이라고 주장하지 않는다.

## 분석 범위와 판정 기준

범위는 `supplied_top_level_ipv4_inbound_new_flow_lab_cases_only`이다. 제공된 root 규칙의 신규 IPv4 유입 패킷 사례만 분석한다. TCP 사례는 source port 50000의 새 SYN, ICMP 사례는 echo-request이며 IPv4 옵션·조각·기존 state·NAT 변경 등은 포함하지 않는다. LAN→Alpine 사례도 root의 LAN ingress 결정만 보는 것으로, 전체 양방향 전달 성공을 증명하지 않는다.

Action, Direction, Interface/인터페이스 부정, Family, Protocol, Source, Destination, 양쪽 port, Quick, 순서, ICMP type을 분석한다. Quick은 일치하면 종료하며 non-Quick은 마지막 일치를 적용한다. 알 수 없는 테이블/주소/그룹이나 지원하지 않는 PF 기능은 일치 여부 불명으로 전파한다. 불명확한 상위 Quick 차단을 단순히 건너뛰어 하위 허용만 적용하지 않는다.

검사하는 여덟 패킷 사례:

| 사례 | 기대 |
|---|---|
| hn1, Windows 10.77.40.10 → Alpine 10.77.50.10 TCP/8080 | pass |
| hn1, Windows → 10.77.40.1 TCP/80 | pass |
| hn1, Windows → 10.77.40.1 TCP/443 | pass |
| hn0, 10.77.50.10 → 10.77.50.1 ICMP echo-request | pass |
| hn0, 10.77.50.11 → 10.77.50.1 ICMP echo-request | block |
| hn0, 10.77.50.10 → 10.77.50.1 TCP/443 | block |
| hn0, 10.77.50.10 → 10.77.50.1 TCP/22 | block |
| hn1, Windows → Alpine ICMP echo-request(복구 경로) | pass |

이 주소들로 패킷을 보내지 않는다. 스냅샷과 고정 사례를 대조할 뿐이다. 구조상 필요한 기본 차단, LAN 기본 IPv4 허용, LAN HTTP/HTTPS 허용, WAN 호스트 ICMP 예외를 함께 확인한다. 필수 구조가 누락되거나 앵커/미지원 기능/무결성/적용 조건이 불명확하면 NEEDS_REVIEW다. 필요한 범위가 확립되고 특정 root 사례가 명확히 기대와 충돌하면 그 스냅샷 범위의 FAIL이다. 모든 필수 구조 및 사례가 증명된 경우에만 제한 범위 PASS가 가능하다. 전체 방화벽의 안전성은 어느 경우에도 검증 완료로 표시하지 않는다.

단순 문법 오류·빈 파일·해시 불일치·파일/상세 비교 오류는 ERROR이며, 지원하지 않는 기능은 임의 해석하지 않고 NEEDS_REVIEW로 남긴다. `pf_snapshot.rules`에는 안전한 참조 번호와 정규화 필드를 출력한다. 실제 label 본문·원본 줄·입력 경로·임의 주소/테이블 이름은 출력하지 않는다. 알려진 실습 주소 외의 literal은 가린다. 참조 번호로 원본 로컬 파일과 대조할 수 있다. GUI 이름과 PF label/UUID가 같은 개념이라는 가정은 하지 않는다.

## 이번 실제 스냅샷 결과: NEEDS_REVIEW

| 구조 확인 | 스냅샷 관찰 | 필터 순서(0부터) |
|---|---|---:|
| 기본 IPv4 차단 | block / in / inet / any→any | 6 |
| LAN IPv4 기본 허용 | pass / in / quick / hn1 / (hn1:network)→any | 60 |
| LAN HTTP 관리 | pass / in / quick / hn1 / TCP / any→(self):80 | 58 |
| LAN HTTPS 관리 | pass / in / quick / hn1 / TCP / any→(self):443 | 59 |
| WAN 지정 호스트 ICMP | pass / in / quick / hn0 / inet / 10.77.50.10→(hn0) / echoreq | 63 |

다섯 구조가 PRESENT인 것은 확인했지만 적용 조건까지 모두 확정된 것은 아니다. `<sshlockout>`와 `<virusprot>`의 실제 주소 목록, `(self)`, `(hn1:network)`, `(hn0)`의 실제 확장 값이 없다. 특히 상위 Quick 테이블 차단의 가능성을 지울 수 없어 LAN 허용 및 승인 WAN ICMP는 block/pass가 모두 가능한 것으로 남는다. 다른 WAN 호스트 ICMP, WAN TCP/443·22는 제공된 root 규칙 내에서는 block 방향으로 일치하지만 실제 트래픽 결과나 전체 적용 정책에 대한 주장이 아니다.

복구 ICMP도 테이블/주소의 조건 때문에 확정하지 못했다. `LAB-D4-Block-Windows-Alpine`라는 문자열이 없다는 이유로 GUI 규칙의 비활성화를 확정하지 않았다. `gui_rule_identity_verified=false`, `lab_block_policy.gui_rule_disabled_confirmed=false`, `complete_effective_ruleset=false`를 유지한다. 기존 수동 FW-06 PASS는 실제 Ping/로그에 기반한 별도 결과로 유지된다.

과도한 허용 검토사항은 LAN 기본 규칙의 모든 프로토콜/목적지 허용 및 LAN HTTP 평문 관리 허용이다. LAN 기본 허용은 이번 실습 기준이므로 그 자체로 취약 FAIL을 만들지 않았다. 상위 Quick pass가 하위 block과 겹치는 사례는 별도 priority_checks에 가능성으로 기록하며, 현재 제공된 규칙에서는 해당 샘플의 충돌 후보가 검출되지 않았다. 후보 부재는 전체 정책 충돌 부재의 증명이 아니다.

## 추가로 필요한 조회 전용 수집

운영자가 별도 승인된 콘솔에서 아래 **조회 명령만** 실행하여 로컬 증적을 확보할 수 있다. 이 프로그램은 아래 명령을 실행하지 않는다.

```sh
date -u '+%Y-%m-%dT%H:%M:%SZ'
pfctl -si
pfctl -v -s Anchors
pfctl -a '*' -sr
pfctl -a '*' -vvsr
pfctl -s Tables
pfctl -t sshlockout -T show
pfctl -t virusprot -T show
ifconfig -a
pfctl -sn
pfctl -ss
```

각 앵커에 private table이 있으면 해당 앵커의 `pfctl -a '<anchor>' -s Tables` 및 `pfctl -a '<anchor>' -t '<table>' -T show`도 필요하다. 시작/종료 시각과 인터페이스·PF 상태를 함께 기록하여 수집 사이 정책 변화를 확인한다. `pfctl -sr`만으로 모든 앵커를 수집했다고 가정하지 않는다. 재귀 출력은 중괄호/하위 규칙을 포함할 수 있으며 현재의 root 전용 파서는 이를 자동으로 완전 해석하지 않는다. 추후 해당 어댑터와 조회 결과의 무결성 연결이 필요하다.

GUI↔PF 식별자 연결은 운영자가 읽기 전용으로 확보한 규칙 메타데이터/생성 규칙 설명과 PF label을 대조해야 한다. 파일에 이름이 없다는 사실이나 규칙 순번만으로 연결하지 않는다. 실제 전체성 확인에는 위 자료 외에도 적용 중인 인터페이스 그룹·NAT·state·동적 정책과 해당 버전의 동작을 함께 검토해야 한다. 상태 목록/주소/테이블 내용은 민감할 수 있으므로 `evidence/day4/`처럼 Git 제외 경로에서만 관리하고 인증 정보·개인키·원본 설정 전체를 보고서나 Git에 넣지 않는다.

명령·규칙 평가 의미의 공식 근거: [FreeBSD pfctl(8)](https://man.freebsd.org/cgi/man.cgi?query=pfctl&sektion=8), [FreeBSD pf.conf(5)](https://man.freebsd.org/cgi/man.cgi?query=pf.conf&sektion=5). OPNsense에 설치된 PF 버전의 man page와도 대조해야 한다.

## 테스트

추가한 `tests/test_day4_pf_evidence.py`는 합성 PF 데이터만 사용한 unittest 25개다. 실제 장비/원본 tar를 테스트 fixture로 저장하지 않았다. 정상 제한 범위 PASS, 누락/부분 수집, 상위 Quick 허용·하위 차단, non-Quick 순서, 문법 오류, 미지원 구문, 앵커·테이블·동적 주소, 인터페이스 부정/그룹/IPv6, 빈 파일, 해시 및 상세 출력 불일치, tar 무결성·경로 탈출, 비밀 비출력, API 403 독립 보존 및 오프라인 무통신을 검증했다.

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_day4_pf_evidence tests.test_day4_audit tests.test_day4_manual_evidence -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py'
```

Day4 139개 통과. 전체 520개 중 519개 통과, 기존 `test_ec2_owner_deployment_script_syntax` 1개는 Git Bash의 Windows 샌드박스 객체 생성 제한(0xC0000022)으로 실패했다. 기존 테스트 수정/삭제/skip, 실제 방화벽 변경, API 권한 추가, Git commit/push는 수행하지 않았다.
