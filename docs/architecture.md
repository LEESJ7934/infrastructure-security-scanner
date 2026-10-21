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

따라서 포트폴리오에서는 다음처럼 구분하는 것이 정확하다.

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

그래서 보고서 생성 보고서는:

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

현재 스키마는 V5다.

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
- 과거 시점의 완전한 포트 snapshot replay
- 조직별 실제 SLA·법적 의무 판단
- 인증 우회나 파괴적인 exploitation

이 한계를 명시하는 이유는 자동화 결과를 실제 사실보다 강하게 해석하지 않기 위해서다.

## 13. 관련 자료

- [프로젝트 개요](../README.md)
- [검증 범위와 결과](validation.md)
- 소스 코드 및 설정 근거: `../sql/`, `../asset_management/`, `../analysis/`, `../verification/`, `../infra/aws/terraform/`

## AWS V6 extension

The cloud extension is an adapter around the existing scan pipeline, not a replacement scanner.

```text
AWS read-only API
  ├─ EC2 inventory ──> hosts + cloud_resources
  └─ Security Groups ──> cloud_configuration_findings

approved ScopePolicy ──> existing private-IP scanner ──> CVE pipeline
```

CVE findings and AWS configuration findings remain separate data types. AWS discovery never triggers a scan automatically. AWS VPC, IAM, Security Group의 실제 구성은 `infra/aws/terraform/`, 검증 자동화는 `.github/workflows/`와 `tests/`에서 확인할 수 있습니다.
