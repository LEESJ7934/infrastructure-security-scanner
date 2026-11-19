# Architecture

## 1. 목적

이 프로젝트는 단순히 열린 포트를 나열하는 스캐너에서 끝나지 않고,
**승인된 자산을 식별하고, 서비스·버전을 관찰하고, 검토된 CVE 후보를 만들고,
읽기 전용 검증과 외부 위협정보 기반 우선순위를 거쳐 증적·조치이력·보고서까지 남기는**
작은 인프라 보안진단 파이프라인을 목표로 한다.

핵심 설계 원칙은 다음과 같다.

- 허가된 대상만 스캔한다.
- 포트 번호와 실제 서비스 식별 결과를 구분한다.
- 버전 문자열만으로 취약점을 확정하지 않는다.
- 후보, 검증 결과, 위험 우선순위, 조치 상태를 서로 분리한다.
- 오류와 비취약 판정을 같은 의미로 취급하지 않는다.
- 자동화가 기존 검토 상태를 임의로 되돌리지 않는다.
- 보고서는 저장된 결과를 읽기만 하며 앞 단계를 자동 실행하지 않는다.

## 2. 전체 흐름

```text
Approved Scope
      |
      v
Target resolution / limits
      |
      v
TCP / UDP Scan
      |
      v
Service & Version Fingerprint (-sV)
      |
      v
MySQL Current Asset / Port Observation
      |
      v
Reviewed CVE Rule Mapping
      |
      v
CANDIDATE
      |
      v
Read-only CVE Verification
      |
      +----> ERROR / NOT_APPLICABLE / FALSE_POSITIVE 등
      |
      v
POTENTIAL / CONFIRMED / RETEST_REQUIRED ...
      |
      v
CVSS + EPSS + CISA KEV + Asset Context
      |
      v
Explainable P1~P4 / Action
      |
      v
Evidence + Remediation History + Assessment History
      |
      v
JSON / PDF Report
```

스캔, 분석, 검증, 우선순위 평가, 보고서는 각각 별도 명령이다.
한 명령이 다음 단계를 묵시적으로 실행하지 않도록 분리했다.

## 3. 주요 컴포넌트

### `scanner/`

네트워크 대상과 포트 상태를 관찰한다.

- `targets.py`: IP, CIDR, 호스트 이름 입력 정규화
- `scope.py`: 승인 대상, 유효기간, 최대 대상·포트·worker 제한
- `tcp_scanner.py`: TCP 연결 기반 포트 상태 확인
- `udp_scanner.py`: UDP 관찰
- `service_fingerprints.py`: HTTP, SSH, FTP, MySQL 등의 응답 기반 서비스 식별
- `scan_runner.py`: 스캔 실행 흐름 조합

호스트 이름을 입력해도 실제 연결은 승인된 숫자 IP 기준으로 수행한다.
서비스 식별 실패 시 오래된 제품·버전을 최신 결과처럼 재사용하지 않는다.

### `asset_management/` + `db/`

스캔 결과를 단발성 출력이 아니라 자산·이력으로 관리한다.

주요 객체:

- `scan_scopes`: 승인 정책과 정책 해시
- `scans`: 스캔 실행 단위
- `hosts`: 자산대장
- `scan_assets`: 실행별 자산 관찰
- `asset_change_history`: 중요도·담당자·환경 등의 변경 이력
- `ports`: 자산별 현재 서비스 관찰
- `vulns`: 취약점 후보 및 현재 상태
- `vuln_evidence`: 검증 증적
- `remediation_history`: 상태·조치 이력
- `vuln_risk_assessments`: 위험 우선순위 평가 이력

`hosts.host_ip`, `ports(host_id, port, protocol)`,
`vulns(port_id, cve_id, source)` 등 중복 기준을 명확히 두어
반복 스캔과 반복 분석이 같은 사실을 무한히 추가하지 않도록 했다.

## 4. 승인 스코프를 먼저 검사하는 이유

포트 스캐너는 기능 자체보다 **어디에 실행하는가**가 중요하다.
그래서 실제 패킷 전송 전에 다음을 확인한다.

- 현재 시각이 승인 기간 안인지
- 입력 IP/CIDR/호스트가 허용 범위인지
- 대상 수가 최대 한도를 넘지 않는지
- 포트 수가 최대 한도를 넘지 않는지
- worker 수가 허용값을 넘지 않는지

`--dry-run`은 이 계획을 실제 접속·DB 저장 없이 먼저 검증하는 용도다.

기본 예시는 루프백만 허용한다. 외부 대상은 본인 소유 또는 명시적 허가가
있는 경우에만 별도 `scope.local.json`으로 구성한다.

## 5. 서비스 식별과 CVE 후보를 분리한 이유

포트 번호만으로 서비스를 단정하면 오탐 가능성이 크다.
예를 들어 8080 포트가 항상 특정 웹 서버를 의미하지 않는다.

그래서 `-sV`에서는 응답을 읽어 다음을 별도 저장한다.

- service
- product
- version
- fingerprint source
- confidence
- 원본 근거의 제한된 표현

이후 CVE 연결은 `analysis/vuln_rules.json`의 **검토된 작은 규칙집**을 사용한다.
현재 규칙집은 공식 공지를 검토한 4개 CVE만 다룬다.

```text
service fingerprint
       |
       v
product match
       |
       v
numeric version range match
       |
       v
reviewed source exists
       |
       v
CANDIDATE
```

규칙에 없다는 것은 안전하다는 뜻이 아니다.
전체 CVE 검색기를 가장하지 않고, 검토 가능한 범위만 자동화했다.

## 6. 왜 `CANDIDATE`를 바로 `CONFIRMED`로 만들지 않았나

원격 배너는 다음 이유로 실제 설치 상태와 다를 수 있다.

- 서버가 임의의 버전 문자열을 표시할 수 있음
- 배포판이 버전 문자열을 유지한 채 보안 패치를 backport할 수 있음
- 취약점이 특정 설정이나 모듈 활성화에 의존할 수 있음
- HTTP 200 응답 자체는 취약점 재현 증거가 아님

따라서 제품·버전이 영향 범위에 들어가도 초기 상태는 `CANDIDATE`다.

CVE 검증기는 CVE별로 제한된 읽기 전용 확인만 수행한다.
예를 들어 HTTP는 루트 경로의 HEAD 같은 안전한 관찰을 사용하고,
인증·업로드·삭제·공격 payload를 사용하지 않는다.

원격 관찰로 설치 패키지, backport, 설정 조건을 확정할 수 없으면
`POTENTIAL`과 추가 확인 항목을 남긴다.

연결 실패나 timeout은 `FALSE_POSITIVE`가 아니라 `ERROR`다.

## 7. 검증 상태와 증적

상태는 단순 boolean 취약/안전이 아니라 검토 수명주기를 표현한다.

```text
CANDIDATE
   |
   v
POTENTIAL
   +--> FALSE_POSITIVE
   +--> NOT_APPLICABLE
   +--> ERROR
   |
   v
CONFIRMED
   |
   v
RETEST_REQUIRED
   +--> CONFIRMED
   +--> FALSE_POSITIVE
   +--> NOT_APPLICABLE
   +--> ERROR
   |
   v
CLOSED
```

검증 결과는 `vuln_evidence`에 저장하고 파일 증적은 SHA-256을 연결할 수 있다.
상태 변경은 `remediation_history`에 변경 전후 상태, 이유, 변경 주체와 시각을 남긴다.

같은 검증을 반복하면 동일 증적을 무한히 추가하지 않고
관찰 횟수와 최근 확인 시각을 갱신할 수 있다.

## 8. Nuclei와 DVWA의 위치

프로젝트에는 Nuclei 실행과 DVWA 인증·스크린샷을 위한 실습 코드가 남아 있다.
이들은 승인된 로컬 실습환경에서 웹 검증과 증적 수집을 연습하기 위한 구성이다.

다만 최종 CVE 검증의 **검토된 CVE 상태 전이 경로는 CVE별 읽기 전용 verifier**를 사용한다.
Nuclei 결과 하나만으로 자동 `CONFIRMED`를 만드는 구조가 아니다.

검증 도구와 CVE 상태 판정 로직은 용도를 구분했다.

- Nuclei/DVWA: 로컬 검증·증적 실습 도구
- CVE별 verifier: 현재 상태 전이에 사용하는 보수적인 읽기 전용 검증 경로

## 9. 위험 우선순위

취약 여부와 대응 우선순위는 다른 문제다.

`analysis/risk_engine.py`는 다음 입력을 조합한다.

- NVD CVSS
- FIRST EPSS
- CISA KEV
- 자산 중요도
- 인터넷 노출 여부
- 개인정보 처리 여부
- 현재 취약점 상태

정책은 `P1~P4 / UNASSESSED`와 `VERIFY / REMEDIATE / RETEST` 같은 action을 만든다.

예:

- KEV + 인터넷 노출 → 높은 우선순위
- 높은 CVSS + 중요 자산 → 높은 우선순위
- 개인정보 처리 자산 → 일부 우선순위를 한 단계 상향

이 식은 산업 표준 위험 공식이라고 주장하지 않는다.
프로젝트 내부 triage policy이며, 어떤 규칙이 매칭됐는지와 방법론 해시를 저장한다.

외부 API 오류나 누락 점수는 0점으로 바꾸지 않는다.
불완전한 평가는 `incomplete` 또는 `UNASSESSED`로 남긴다.

## 10. 보고서가 읽기 전용인 이유

보고서를 생성하는 순간 스캔이나 외부 API를 다시 실행하면
보고서 내용이 이전 단계의 저장 결과와 달라질 수 있다.

따라서 보고서는 다음 원칙으로 생성한다.

- 하나의 consistent read transaction에서 DB snapshot 조회
- INSERT / UPDATE / DELETE 없음
- 스캔 대상 접속 없음
- NVD/FIRST/CISA/Shodan 재조회 없음
- 같은 snapshot으로 JSON과 PDF 생성
- canonical snapshot SHA-256 기록

방식을 사용한다.

최신 평가가 현재 finding 상태·자산 context와 맞으면 `CURRENT`,
다르면 `STALE`, 없으면 `MISSING`으로 표현한다.

이 `CURRENT`는 외부 위협정보가 지금도 최신이라는 뜻이 아니라
**저장된 평가 context가 현재 DB snapshot과 일치한다는 뜻**이다.

## 11. 데이터베이스 설계의 핵심

자산·취약점·조치 이력의 핵심 구조는 V5에서 정리했고, 이후 V6(AWS 자산·설정)와 V7(검증 증적) 관련 테이블을 추가했다.

주요 설계 판단:

1. **현재 상태와 이력 분리**
   - `vulns`에는 현재 상태
   - `remediation_history`에는 상태 변화
   - `vuln_risk_assessments`에는 평가 이력

2. **자산 정보와 관찰 정보 분리**
   - `hosts`에는 현재 자산 메타데이터
   - `scan_assets`에는 실행별 관찰
   - `ports`에는 최신 포트 상태

3. **중복 방지**
   - 반복 스캔·분석·평가가 동일 사실을 중복 삽입하지 않도록 UNIQUE/해시 사용

4. **마이그레이션 보존**
   - V1→V5 개선 과정에서 기존 데이터를 삭제하지 않고 백업·검증 후 구조 확장

## 12. 의도적인 한계

이 프로젝트는 상용 ASM·취약점 관리 제품을 대체하지 않는다.

지원하지 않거나 제한적인 부분:

- 모든 Nmap scan technique 복제
- OS fingerprinting 전체 구현
- 모든 서비스 프로토콜의 완전한 버전 식별
- 전체 CVE 데이터베이스 자동 매칭
- 원격 관찰만으로 배포판 backport 확정
- V8 이전 관찰의 과거 snapshot 복구 및 과거 시점의 자산/판정 전체 재현
- 조직별 실제 SLA·법적 의무 판단
- 인증 우회나 파괴적인 exploitation

이 한계를 명시하는 이유는 자동화 결과를 실제 사실보다 강하게 해석하지 않기 위해서다.

## 13. 관련 자료

- [프로젝트 개요](../README.md)
- [검증 범위와 결과](audit-evidence-mapping.md)
- 소스 코드 및 설정 근거: `../sql/`, `../asset_management/`, `../analysis/`, `../verification/`, `../infra/aws/terraform/`

## 14. AWS 자산·설정 점검 확장

AWS 기능은 기존 스캔 로직을 교체하지 않고, 자산 조회와 설정 점검을 추가하는 구조다.

```text
AWS read-only API
  ├─ EC2 inventory ──> hosts + cloud_resources
  └─ Security Groups ──> cloud_configuration_findings

approved ScopePolicy ──> existing private-IP scanner ──> CVE pipeline
```

CVE 후보와 AWS 설정 점검 결과는 별도 데이터로 관리한다. AWS 자산 조회 결과가 스캔 승인으로 이어지지는 않는다. VPC·IAM·Security Group 설정은 `infra/aws/terraform/`, 검증 코드는 `.github/workflows/`와 `tests/`에서 확인할 수 있다.

## 15. 진단 신뢰성 및 V8 관찰 이력

TCP 연결 거부만 `closed`, timeout은 `unknown`, 권한/네트워크/호스트 오류는 `error`로 남긴다. 무응답만으로 filtered를 확정하지 않는다. UDP는 IPv4/IPv6 connected datagram을 사용하며 응답은 open, 명시적 port unreachable은 closed, 무응답은 open|filtered다. 이 구분과 reason/error, 서비스의 observed/guessed 출처는 CLI·JSON에서 보존한다.

CLI와 함수 기본은 `1-1024`다. `--profile lab`은 DBMS·DVWA·Kibana·HTTP·Elasticsearch 접점을 포함하지만 승인 scope의 대상·포트 수·worker 제한을 그대로 적용한다. 전체 범위 `--ports 1-65535`도 별도 scope 승인 없이 제한을 우회하지 않는다. 모든 범위는 상한을 먼저 검증하며 작업 큐는 worker 수로 제한한다. 중단/deadline 이후 미실행 항목은 not_tested다. 이미 진행 중인 socket 작업은 최대 해당 timeout까지 정리한다.

새 스캔은 UTC offset을 가진 수집 시각과 monotonic duration을 기록한다. DB DATETIME 경계에서 UTC로 변환하며, 출처 불명인 기존 naïve 시각은 보정하거나 Z를 붙이지 않는다. V8 이전 KST/UTC 혼합 데이터에 일괄 시간 보정은 수행하지 않는다.

```bash
python -m scripts.run_scan scan --target 127.0.0.1 --ports 4280,5601,9200 -sV --no-db --output-json <새결과.json>
python -m scripts.import_scan_results --input <보존결과.json>
```

일반 실행도 DB 접근 전에 비민감 원시 JSON을 별도 신규 경로에 flush/fsync한다. DB 실패 시 그 파일을 명시적으로 재수입할 수 있다. HTTP 배너는 식별에 필요한 허용 헤더만 남기고 body·cookie·인증 헤더와 임의 확장 헤더를 제외한다. 동일 파일 경로를 덮어쓰지 않는다. Nmap은 선택 비교 도구이며 스캐너가 모르는 버전을 임의 보충하지 않는다. Kibana/Elasticsearch는 제품 전용 HTTP 헤더가 관찰될 때만 reported 제품으로 식별하고, 버전 헤더가 없으면 버전은 unknown이다.

### V8 마이그레이션 및 호환성

`sql/migration_v8.sql`은 운영 DB에 자동 적용되지 않는다. V7 백업과 격리 검증 후 운영자가 대상 DB를 명시 선택해야 한다. 기존 init.sql과 migration_v7.sql이 준비된 DB에 **한 번** 적용하는 migration이다. 자동 반복 실행·DROP DATABASE·기존 기록 초기화는 지원하지 않는다.

- `scan_run_snapshots`: 원시 실행의 해시·요청 범위·UTC/LEGACY_UNSPECIFIED·namespace·JSON을 보존한다.
- `scan_port_observations`: 실행/자산/endpoint별 open·closed·filtered·open|filtered·unknown·error·not_tested와 실제 시각·근거를 append-only로 저장한다.
- `finding_observation_links`: 후보/양성 검증의 원래 관찰 연결을 보존한다. 동일 실행 UID의 동일 내용은 재사용하고 다른 내용은 충돌로 거절한다.
- `ports`는 현재 요약이며 부분 범위 스캔이 다른 endpoint 이력을 지우지 않는다. 늦게 수입된 과거 UTC 실행·출처 불명 시각은 더 최신의 명시 UTC 관찰을 대체하지 않는다.
- `hosts(asset_namespace, host_ip)`로 고객/VPC namespace를 구분한다. 기본 `legacy`는 기존 동작을 유지한다. 기존 IP를 임의 고객/VPC로 자동 추정하지 않는다.

V8 미적용 DB는 기존 경로를 유지하면서 `LEGACY_CURRENT_STATE_ONLY`를 표시한다. 그 DB에서 새 namespace·불변 이력이 있다고 주장하지 않는다. 기존 데이터는 새 실측 관찰로 backfill하지 않는다. V8의 scan 선택은 포트 관찰을 재생하지만 자산 메타데이터와 review status는 현재값이다. 완전한 과거 시점 판정 snapshot으로 설명하지 않는다.

과거 CONFIRMED는 삭제하지 않는다. 현재 관련성 CURRENT/STALE/NOT_REOBSERVED와 `effective_status`를 분리한다. 제품/관찰이 달라지면 과거 확정 상태를 현재 확정 건수에 더하지 않으며, 같은 광고 버전이어도 새 관찰에 양성 증거가 연결되지 않으면 RETEST_REQUIRED다.

### 위협정보와 패키지 검토

NVD·FIRST·CISA 실제 fetch는 fetched_at을 기록한다. 자체 TTL은 CVSS 7일, EPSS 2일, KEV 1일이며 공급자 보증기간이 아니다. EPSS 원관측일도 검사한다. 최신 다운로드로 오래된 EPSS를 갱신된 관측처럼 만들지 않는다. 명시적 stale/비정상 시각은 새 우선순위 산정에서 제외하고, 옛 기록의 조회 시각은 UNKNOWN으로 남긴다. 보고서 생성 중 외부 정보를 재조회하지 않는다.

`analysis.package_evidence`는 지원 배포판·release·설치 패키지·CVE·공식 vendor advisory·검토자·시각·증적 hash가 연결된 검토를 REPORTED_*로 내보낸다. 배너 suffix로 백포트 여부를 추정하거나 자동으로 finding을 닫지 않는다. source 인증과 실제 patch 검증은 별도로 남긴다.

설정 진단의 기존 도메인 asset_id와 DB UUID는 `asset_management.audit_binding.bind_audit_results()`의 명시 crosswalk로 연결할 수 있다. supplemental CLI의 `--asset-bindings`도 같은 함수를 쓴다. 매핑 선언은 DB 검증 완료가 아니며 원래 ID·판정·수집 시각을 바꾸지 않는다. 모든 도메인 결과의 자동 DB 수입을 구현한 것은 아니다.
