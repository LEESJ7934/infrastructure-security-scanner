# Port Scanner Database Schema V5

> 현재 통합 기준은 **MySQL 8.0 / 프로젝트 스키마 V7**입니다. 아래 V5/V6 구조 설명은 기존 기반을 보존한 것입니다. `sql/init.sql`은 V6를 만들며 V7은 `sql/migration_v7.sql`을 별도로 적용합니다. V7의 `lab_verification_results`는 scan/port/asset 외래키, 실행 상태·판정·Scope·시각·증적 SHA-256을 보존합니다. `NOT_TESTED`는 DB enum이 아닌 보고서 커버리지입니다. [백업·적용 절차](windows_mysql_ec2_evidence.md)와 [현재 README](../README.md)를 함께 확인합니다.


## 1. 개선 목적

기존 스키마는 취약점 상태가 `POTENTIAL`, `CONFIRMED`,
`REJECTED`로 제한되어 있었지만 검증 코드는 `INVALID`,
`ERROR`, `SKIP`도 반환했다.

이번 개선에서는 다음 요구사항을 반영했다.

- 스캔, 자산, 포트, 취약점, 검증 증적, 조치 이력 분리
- 동일 취약점의 중복 저장 방지
- 탐지부터 조치 완료까지 상태 추적
- 검증 결과와 스크린샷의 증적 관리
- 기존 V1 데이터 보존 마이그레이션
- 승인된 스캔 범위와 정책 해시 보존
- 자산 중요도·담당자·환경·데이터 등급 관리
- 스캔별 자산 관찰 및 자산 변경 감사이력

## 2. 테이블 관계

```mermaid
erDiagram
    SCAN_SCOPES ||--o{ SCANS : authorizes
    SCANS ||--o{ HOSTS : "last scan"
    SCANS ||--o{ SCAN_ASSETS : observes
    SCANS ||--o{ PORTS : "last scan"
    HOSTS ||--o{ SCAN_ASSETS : appears
    HOSTS ||--o{ ASSET_CHANGE_HISTORY : changes
    HOSTS ||--o{ PORTS : owns
    PORTS ||--o{ VULNS : exposes
    VULNS ||--o{ VULN_EVIDENCE : supports
    VULNS ||--o{ REMEDIATION_HISTORY : tracks
    VULNS ||--o{ VULN_RISK_ASSESSMENTS : prioritizes
```

## 3. 테이블별 역할

### scan_scopes

허가된 스캔 범위, 승인 근거, 유효기간과 실행 한도를 관리한다.
`policy_sha256`은 정규화된 스코프 정책의 SHA-256 값이다.

### scans

한 번의 포트 스캔 실행을 기록한다.

| 필드 | 의미 |
|---|---|
| `id` | DB 내부 숫자 식별자 |
| `scan_uid` | 애플리케이션에서 생성한 고유 스캔 ID |
| `scope_id` | 승인 스코프의 DB ID |
| `target` | 스캔 대상 |
| `requested_targets` | 사용자가 입력한 IP·CIDR·호스트 목록 |
| `scan_type` | TCP, UDP 또는 TCP+UDP |
| `port_range` | 검사한 포트 범위. V3.1부터 MEDIUMTEXT, 연속 포트는 `1-1024`처럼 저장 |
| `status` | 스캔 실행 상태 |
| `config_snapshot` | 실행 당시 설정 |

`scan_uid`에는 UNIQUE 제약조건을 적용해 같은 스캔 결과가
중복 저장되지 않도록 한다.

### hosts

발견한 호스트를 자산대장으로 관리한다.

| 필드 | 의미 |
|---|---|
| `host_ip` | IPv4 또는 IPv6 주소 |
| `asset_uid` | IP와 독립된 UUID 자산 식별자 |
| `host_name` | 역방향 DNS 조회 결과 |
| `asset_name` | 업무 자산명 |
| `asset_type` | 자산 유형 |
| `environment` | 운영·개발·테스트 등 환경 |
| `criticality` | 업무 중요도 |
| `owner` | 담당자 |
| `data_classification` | 데이터 분류 등급 |
| `handles_personal_data` | 개인정보 처리 여부 |
| `internet_exposed` | 인터넷 노출 여부 |
| `lifecycle_status` | 활성·비활성·폐기 상태 |
| `first_seen` | 최초 발견 시각 |
| `last_seen` | 최근 발견 시각 |
| `last_scan_id` | 최근 확인한 스캔의 DB ID |

`host_ip`에는 UNIQUE 제약조건을 적용한다.

### scan_assets

한 번의 스캔과 여러 자산을 연결한다. 원래 입력값, IP 해석 방식,
스캔 결과와 열린 포트 수를 실행별로 보존한다.

### asset_change_history

자산 중요도, 담당자, 환경, 수명주기 상태 등의 변경 전후 값과
사유·변경자를 보존한다.

### ports

자산별 네트워크 포트와 서비스 식별 결과를 관리한다.

중복 판단 기준은 다음 세 필드의 조합이다.

```text
host_id + port + protocol
```

같은 포트를 다시 스캔하면 새 행을 만들지 않고 서비스,
버전, 배너, 상태, 마지막 발견 시각을 갱신한다.

### vulns

포트에서 발견한 취약점 후보와 현재 검토 상태를 관리한다.

중복 판단 기준은 다음 세 필드의 조합이다.

```text
port_id + cve_id + source
```

CVE 후보 재분석은 후보와 탐지 근거를 저장하며 검토 상태를 CANDIDATE로 되돌리지 않는다.
위험도 평가는 외부 정상 관측일 때만 `cvss`/`epss` summary를 갱신하고 조회 오류에서는 기존 값을 보존한다.
`epss`는 V5에서 `DECIMAL(10,9) NULL`이다.
`risk`는 과거 weighted score를 보존한 legacy 필드이며 현재 우선순위에는 사용하지 않는다.
현재 규칙 기반 우선순위와 근거는 `vuln_risk_assessments`에 별도로 저장한다.

### vuln_evidence

취약점 검증 과정에서 생성한 증적을 저장한다.

| 증적 유형 | 의미 |
|---|---|
| `HTTP_RESPONSE` | HTTP 상태 및 응답 확인 결과 |
| `SCREENSHOT` | 웹 서비스 화면 캡처 |
| `NUCLEI` | Nuclei 템플릿 검증 결과 |
| `BANNER` | FTP 등 서비스 배너 검증 결과 |
| `MANUAL` | 수동 점검 증적 |
| `ERROR_LOG` | 검증 도구 실행 오류 |

파일 증적에는 SHA-256 값을 함께 저장할 수 있다. 이를 통해
수집 이후 파일이 변경됐는지 확인할 수 있다.

### remediation_history

취약점 상태 변경과 조치 내역을 시간순으로 보존한다.

| 필드 | 의미 |
|---|---|
| `from_status` | 변경 전 상태 |
| `to_status` | 변경 후 상태 |
| `action_type` | 상태 변경, 재점검, 조치, 종료, 재개 |
| `reason` | 변경 또는 판단 사유 |
| `changed_by` | 변경 주체 |
| `changed_at` | 변경 시각 |

현재 상태만 저장하는 방식과 달리 누가, 언제, 왜 상태를
변경했는지 확인할 수 있다.

### vuln_risk_assessments

위험도 평가의 평가 입력·판정·출처를 finding별로 보존한다. `vuln_id`가 `vulns.id`를 참조하며
finding 삭제 시 ON DELETE CASCADE가 적용된다.

| 필드 | 의미 |
|---|---|
| `methodology_id`, `methodology_sha256` | 프로젝트 triage policy의 ID와 정의 해시 |
| `vuln_status`, `action`, `priority` | 평가 당시 상태, VERIFY/REMEDIATE/RETEST, P1~P4/UNASSESSED |
| `cvss_score/version/vector/source` | 선택한 CVSS metric과 출처 |
| `epss_score/percentile/date` | FIRST 관측값; score/percentile은 DECIMAL(10,9) |
| `kev_status`, `kev_date_added` | KNOWN_EXPLOITED / NOT_LISTED / UNKNOWN 및 등록일 |
| `asset_criticality`, `internet_exposed`, `handles_personal_data` | 평가 당시 자산 context |
| `details` | 정규화된 source 결과, 규칙, 이유, 누락 입력, 오류, metadata JSON |
| `input_sha256` | 시각/횟수를 제외한 canonical 평가 입력과 결과의 해시 |
| `first_assessed_at`, `last_assessed_at`, `observations` | 최초/최근 평가 시각과 동일 결과 관측 횟수 |

UNIQUE 기준은 `(vuln_id, methodology_id, input_sha256)`이다.
동일 입력 재평가는 기존 행을 재사용하고 last_assessed_at과 observations를 갱신한다.
따라서 최신 assessment는 가장 큰 ID가 아니라 `last_assessed_at DESC, id DESC`로 선택한다.
priority와 last_assessed_at 검색용 index가 있다.
위험도 평가는 status/검증일/종료일/조치이력을 변경하지 않는다.
CISA due_date는 JSON 출처 metadata이며 사용자 조직의 의무 SLA가 아니다.

## 4. 표준 상태값

### 스캔 상태

| 상태 | 의미 |
|---|---|
| `QUEUED` | 실행 대기 |
| `RUNNING` | 실행 중 |
| `COMPLETED` | 정상 완료 |
| `PARTIAL` | 일부 대상만 완료 |
| `FAILED` | 전체 실행 실패 |

### 취약점 상태

| 상태 | 의미 |
|---|---|
| `CANDIDATE` | 규칙으로 식별된 초기 후보 |
| `POTENTIAL` | 분석을 마쳤으며 검증이 필요한 상태 |
| `CONFIRMED` | 기술적 검증으로 확인된 취약점 |
| `NOT_APPLICABLE` | 대상 서비스에 검증을 적용할 수 없음 |
| `FALSE_POSITIVE` | 취약점이 재현되지 않음 |
| `RETEST_REQUIRED` | 조치 후 재점검이 필요한 상태 |
| `CLOSED` | 조치와 재점검이 완료된 상태 |
| `ERROR` | 검증 도구 또는 실행 환경 오류 |

## 5. 상태 흐름

```mermaid
flowchart TD
    A[CANDIDATE] --> B[POTENTIAL]
    B --> C[CONFIRMED]
    B --> D[FALSE_POSITIVE]
    B --> E[NOT_APPLICABLE]
    B --> F[ERROR]
    C --> G[RETEST_REQUIRED]
    G --> C
    G --> D
    G --> E
    G --> F
    G --> H[CLOSED]
    H --> G
```

`POTENTIAL`에서 바로 `CLOSED`로 변경하지 않는다. 먼저 실제
취약점임을 확인하고 조치 및 재점검 과정을 거치도록 제한한다.

## 6. 기존 상태 변환

| V1 값 | V2 값 |
|---|---|
| 스캔 `DONE` | `COMPLETED` |
| 취약점 `REJECTED` | `FALSE_POSITIVE` |
| 검증기 `INVALID` | `FALSE_POSITIVE` |
| 검증기 `SKIP` | `NOT_APPLICABLE` |

검증기의 원본 결과는 `vuln_evidence.details`에 보존하고,
`vulns.status`에는 표준화한 상태만 저장한다.

## 7. 설치 및 마이그레이션

### 신규 설치

빈 MySQL 볼륨에서 Docker Compose를 시작하면
`sql/init.sql`이 자동으로 실행되어 V5 구조를 생성한다.

```powershell
docker compose -f .\docker\docker-compose.yml up -d
```

### 기존 V1 DB

`sql/migration_v2.sql`을 한 번만 실행한다.

마이그레이션은 다음 백업 테이블을 먼저 생성한다.

- `migration_backup_scans_v1`
- `migration_backup_hosts_v1`
- `migration_backup_ports_v1`
- `migration_backup_vulns_v1`

기존 문자열 `last_scan_id`는 삭제하지 않고
`legacy_last_scan_uid`로 이름을 변경해 보존한다.

V1 DB는 먼저 V2 마이그레이션과 검증을 완료해야 한다.

### 기존 V2 DB

DB 덤프를 만든 뒤 `sql/migration_v3.sql`을 한 번 실행한다.
이어서 `sql/migration_v3_1.sql`로 포트 범위 저장 컬럼을 확장한다.
자세한 명령과 검증 기준은 `docs/asset_management.md`에 있다.

### 기존 V3 DB

현재 DB를 백업한 뒤 `sql/migration_v3_1.sql`로 V3.1 구조를 적용한다.
`scans.port_range`를 VARCHAR(100)에서 MEDIUMTEXT로 확장하여
여러 개의 떨어진 포트를 지정한 긴 목록도 보존한다.
애플리케이션은 실제 검사한 포트를 `22,80-82,443`처럼 정리하며,
사용자 입력 원문은 `scans.config_snapshot`의 `ports`에 보존한다.

### 기존 V3.1 / V4 DB

V3.1에서는 `migration_v4.sql`로 ports.product/fingerprint를 추가한 뒤 V4 검증을 한다.
V4에서는 외부 덤프를 백업하고 `migration_v5.sql`을 실행한다.
V5는 vulns.epss precision 확장과 vuln_risk_assessments 생성만 포함한다.
`verify_v5.sql`을 전후 실행해 기존 count 보존과 신규 구조를 확인한다.
MySQL DDL은 implicit commit이 있으므로 전체 migration을 transaction rollback으로 복구할 수는 없다.

### 현재 V5 / 보고서 생성

이미 V5라면 보고서 생성을 위한 migration이나 init.sql 재실행은 없다.
보고서는 READ ONLY / REPEATABLE READ / consistent snapshot으로 조회하고 rollback으로 읽기 transaction을 종료한다.
INSERT/UPDATE/DELETE/commit과 외부 source 재조회는 하지 않는다.
보고서 JSON/PDF는 DB 밖의 `reports/`에 생성된다.

## 8. 검증 SQL

```sql
SHOW TABLES;

SHOW COLUMNS FROM scans;
SHOW COLUMNS FROM scan_scopes;
SHOW COLUMNS FROM hosts;
SHOW COLUMNS FROM scan_assets;
SHOW COLUMNS FROM asset_change_history;
SHOW COLUMNS FROM vulns;
SHOW COLUMNS FROM vuln_evidence;
SHOW COLUMNS FROM remediation_history;
SHOW COLUMNS FROM vuln_risk_assessments;
SHOW COLUMNS FROM vulns LIKE 'epss';

SELECT status, COUNT(*)
FROM vulns
GROUP BY status;

SELECT
    port_id,
    cve_id,
    source,
    COUNT(*) AS duplicate_count
FROM vulns
GROUP BY
    port_id,
    cve_id,
    source
HAVING COUNT(*) > 1;
```

마지막 중복 검사 결과가 0행이면 UNIQUE 기준에 맞게 정리된
상태다.

## 9. 운영 및 보안 관점

- MySQL 포트는 `127.0.0.1`에만 바인딩한다.
- DB 비밀번호는 `.env`에서만 관리하고 커밋하지 않는다.
- 취약점 상태 변경 사유와 변경 주체를 이력으로 남긴다.
- 검증 결과와 증적 파일의 SHA-256 값을 연결한다.
- 자동 분석이 검증 완료 상태를 임의로 되돌리지 않게 한다.
- 중복 방지는 애플리케이션과 UNIQUE 제약조건 양쪽에서
  수행한다.
- 스캔 전에 승인 범위와 유효기간 및 실행 한도를 검증한다.
- 자산 메타데이터 변경에는 변경자와 사유를 반드시 남긴다.


## V4 추가: 제품 식별과 CVE 후보 근거

기존 V3/V3.1 데이터와 자산·스캔 관계는 유지합니다.

| 테이블/컬럼 | 형식 | 의미 |
|---|---|---|
| `ports.product` | `VARCHAR(100) NULL` | `apache_http_server`, `openssh` 등 식별된 제품 |
| `ports.fingerprint` | `JSON NULL` | 파서 버전, 근거, 서비스·제품·버전, 식별 출처, 프로브 오류, TLS 식별 정보 |
| `vuln_evidence` (기존 테이블 재사용) | `checker=cve_catalog_mapper`, `evidence_type=BANNER` | 후보 선정 이유, CVE 출처, 영향 범위, 규칙 해시, 스캔 ID를 JSON details로 보존 |

새 CVE 후보는 `CANDIDATE`, 미조회 `cvss/epss/risk`는 `NULL`입니다.
같은 포트/CVE/출처의 후보는 기존 UNIQUE 키로 중복 방지합니다.
동일 근거는 후보 행 잠금 아래 `vuln_id/checker/sha256`로 조회해 중복 삽입을 방지합니다.
이미 검토한 상태와 ERROR 상태는 후보 재저장으로 되돌리지 않습니다.

분석은 자산의 마지막 스캔에 속한 열린 TCP 관찰값만 사용합니다.
`ports`의 모든 과거 상태를 저장하는 스냅샷 테이블은 추가하지 않았습니다.
새 관찰에서 식별 정보가 없으면 이전 제품/버전을 비워 오래된 값을 재사용하지 않습니다.

V3.1에서 V4로 이동할 때는 `migration_v4.sql`을 사용합니다. 이후 V5 적용은 위 절차를 따릅니다.
`verify_v4.sql`은 구조·후보·근거·중복·폐기한 규칙의 기존 기록을 읽기 전용으로 확인합니다.
자세한 실행 절차: [서비스·CVE 매핑 안내](service_cve_mapping.md).

## 보고서 생성 보고서의 현재 상태 해석

자산 선택은 `p.last_scan_id = h.last_scan_id`, scan 선택은 `p.last_scan_id = 선택한 scan ID`이다.
현재 관찰의 모든 endpoint에 연결된 reviewed finding을 포함하고, 열린 포트 수는 state=open만 센다.
관찰되지 않은 과거 endpoint와 legacy rule은 현재 finding 수에 포함하지 않는다.
과거 scan을 선택해도 historical replay가 되지 않는다.

최신 평가의 vuln_status/criticality/exposure/개인정보 처리 여부를 현재 DB context와 비교한다.
JSON에 보존된 추가 자산/endpoint/CVE/source context가 있으면 함께 비교한다.
일치하면 CURRENT, 변경되었으면 STALE, assessment가 없으면 MISSING이다.
STALE/MISSING은 요약에서 UNASSESSED로 처리하고 기존 평가는 과거 이력으로 표시한다.
CURRENT는 source API를 새로 조회했다는 뜻이 아니다.

JSON snapshot의 SHA-256에서는 generated_at과 hash 자체를 제외한다.
이 값은 내용 동일성 확인용이며 전자서명이나 DB 원본의 진위를 증명하는 값은 아니다.

## V6 AWS cloud extension

V6 keeps the existing `hosts` table as the scanner's primary asset identity and adds two AWS-specific tables.

```text
hosts
  1 ─── 0..1 cloud_resources
              1 ─── 0..N cloud_configuration_findings
```

### cloud_resources

Stores normalized EC2 context for a `CLOUD_RESOURCE` host: AWS account, region, instance ID, VPC/subnet, primary private/public IP, instance state, Security Group snapshot and sanitized tags.

`UNIQUE(provider, account_id, region, resource_id)` prevents duplicate EC2 identities and `UNIQUE(host_id)` keeps one current cloud context per host.

### cloud_configuration_findings

Stores AWS configuration findings separately from `vulns` so a Security Group exposure is never represented as a CVE. Current V6 rules focus on Internet-wide SSH/RDP/database ingress and all-port/all-protocol ingress.

A repeated rule updates the same row and increments `observations`. A later review that no longer sees the rule sets `status=RESOLVED` and `resolved_at`.

### Scope limitation

The pre-existing `hosts.host_ip` uniqueness is IP-centric. V6 therefore persists one VPC at a time (`--vpc-id` required with `--save`) and does not claim multi-account/overlapping-RFC1918 asset identity support.
