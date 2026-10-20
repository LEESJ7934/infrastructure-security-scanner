# 인프라 보안 진단 스캐너

**Infrastructure Security Scanner**

자산 식별부터 포트 스캔, 취약점 후보 관리, 검증 증적과 조치
이력까지 연결하는 인프라 보안진단 프로젝트입니다.

포트 스캔은 본인 소유 시스템이나 명시적으로 허가받은
시스템에서만 실행해야 합니다. 기본 스코프는 로컬 루프백
환경만 허용합니다.

## 주요 기능

- 단일 IPv4/IPv6, CIDR, 호스트 이름 입력
- 승인 스코프와 유효기간 사전 검증
- 최대 대상·포트·동시 작업 수 제한
- 자산 고유 ID, 중요도, 담당자, 환경, 데이터 등급 관리
- 개인정보 처리 및 인터넷 노출 여부 관리
- 스캔별 자산 관찰 결과와 자산 변경 감사이력 저장
- 취약점 상태, 검증 증적, 조치이력 관리
- TCP 배너의 제품·버전 식별, 공식 공지 4개 CVE의 검토된 규칙집
- 분석 미리보기와 CANDIDATE 저장, 선정 이유·출처·규칙 해시 보존
- CVE별 읽기 전용 검증과 증적 중복 방지
- CVSS/EPSS/KEV·자산 맥락 기반의 설명 가능한 우선순위
- 현재 관찰값·평가 freshness·증적·조치이력의 JSON/PDF 보고서

## 아키텍처 요약

```text
승인 Scope
  → TCP/UDP Scan
  → Service/Version Fingerprint
  → Asset/Port Observation
  → Reviewed CVE Candidate
  → Read-only Verification
  → CVSS/EPSS/KEV + Asset Context
  → Explainable Priority
  → Evidence/Remediation History
  → JSON/PDF Report
```

### 시연 화면

실제 스캔·위험도 평가·PDF 보고서·AWS 점검 화면은 민감정보가 없는 캡처만 `docs/images/`에 추가합니다. 현재 저장소에는 재현 가능한 실행 명령과 검증 문서를 제공합니다.

> 공개 캡처에는 실제 IP, AWS 계정 식별자, 자산 UUID, 내부 호스트명 등 식별 가능한 값을 마스킹합니다.

단계별 판단과 저장 의미는 [아키텍처 문서](docs/architecture.md)에,
실제 검증 범위와 E2E 기록은 [검증 문서](docs/validation.md)에 정리했습니다.


## 1. 실행 환경 준비

Windows PowerShell 기준입니다.

Python 3.10 이상과 Docker Desktop이 필요합니다.

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -r .\requirements.txt
```

환경변수 파일을 만듭니다.

```powershell
Copy-Item .\.env.example .\.env
```

`.env`의 `replace_locally` 값을 로컬 비밀번호로 변경합니다.
`.env`는 Git에 커밋하지 않습니다.

## 2. MySQL 실행

```powershell
docker compose -f .\docker\docker-compose.yml up -d
docker compose -f .\docker\docker-compose.yml ps
docker inspect -f "{{.State.Health.Status}}" portscan-mysql
```

새 볼륨에서는 V6가 반영된 `sql/init.sql`이 자동 실행됩니다.
기존 DB는 외부 덤프를 백업하고 현재 버전에서 순서대로 마이그레이션합니다.

| 현재 DB | 실행할 파일 |
|---|---|
| V2 | `migration_v3.sql` → `migration_v3_1.sql` → `migration_v4.sql` → `migration_v5.sql` → `migration_v6.sql` |
| V3 | `migration_v3_1.sql` → `migration_v4.sql` → `migration_v5.sql` → `migration_v6.sql` |
| V3.1 | `migration_v4.sql` → `migration_v5.sql` → `migration_v6.sql` |
| V4 | `migration_v5.sql` → `migration_v6.sql` |
| V5 | `migration_v6.sql` |
| V6 (AWS 확장) | 실행할 마이그레이션 없음 |

백업·오류 확인을 포함한 PowerShell 절차는
[서비스·CVE 매핑 실행 안내](docs/service_cve_mapping.md)를 따릅니다.
기존 V2/V3 마이그레이션은 재실행하지 않습니다.
기존 보안진단 기준 DB는 V5였고 AWS 확장 후 현재 기준 DB는 **V6**입니다.

기존 저장소에서 생성한 DB를 계속 사용할 경우, 개발 단계 이름이 남아 있던 내부 식별자를 의미 기반 이름으로 정리하기 위해 `sql/migration_semantic_identifiers.sql`을 **한 번만** 적용합니다. 새 DB는 이 마이그레이션이 필요하지 않습니다.
V4에서 V5로 이동할 때는 외부 DB 덤프를 만든 뒤 다음을 실행합니다.

```powershell
Get-Content -Raw -Encoding UTF8 .\sql\verify_v5.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
Get-Content -Raw -Encoding UTF8 .\sql\migration_v5.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
Get-Content -Raw -Encoding UTF8 .\sql\verify_v5.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
```

각 명령의 오류를 확인하고 다음 명령을 실행합니다.
`existing_counts_preserved=1`, 기존 데이터 건수 유지, EPSS `DECIMAL(10,9)`,
`vuln_risk_assessments` 생성을 확인합니다. MySQL DDL은 전체 rollback 대상이 아닙니다.

## 3. 승인 스코프 준비

로컬 설정 파일을 복사합니다.

```powershell
Copy-Item .\config\scope.example.json .\config\scope.local.json
```

`scope.local.json`에 승인 문서 번호, 승인자, 유효기간,
허용 대상과 실행 한도를 작성합니다. 이 파일은 실제 내부
대상 정보가 포함될 수 있으므로 Git에서 제외됩니다.

먼저 실제 접속이나 DB 저장이 없는 `--dry-run`으로 확인합니다.

```powershell
py -m scripts.run_scan scan `
  --target 127.0.0.1 `
  --ports 22,80,443 `
  --scope-file .\config\scope.local.json `
  --dry-run
```

승인 범위 밖의 대상, 만료된 허가, 한도를 넘는 요청은 스캔
시작 전에 차단됩니다.

## 4. 스캔 실행

```powershell
py -m scripts.run_scan scan `
  -sT -sV `
  --target 127.0.0.1 `
  --ports 1-1024 `
  --scope-file .\config\scope.local.json `
  -oN .\reports\local_scan.txt
```

여러 입력은 `--target`을 반복합니다.

```powershell
py -m scripts.run_scan scan `
  -sT `
  --target 192.168.56.0/30 `
  --target lab.example.com `
  --ports 22,80,443 `
  --scope-file .\config\scope.local.json `
  --dry-run
```

## 5. 자산대장 관리

자산 목록:

```powershell
py -m scripts.manage_assets list
```

수동 등록 또는 분류 보강:

```powershell
py -m scripts.manage_assets register `
  --ip 127.0.0.1 `
  --name local-lab `
  --type SERVER `
  --environment TEST `
  --criticality LOW `
  --data-classification INTERNAL `
  --no-personal-data `
  --no-internet-exposed `
  --changed-by portfolio-owner `
  --reason "로컬 실습 자산 최초 분류"
```

자산 상세 조회와 변경:

```powershell
py -m scripts.manage_assets show --asset-id <ASSET_ID>

py -m scripts.manage_assets update `
  --asset-id <ASSET_ID> `
  --criticality HIGH `
  --owner security-team `
  --changed-by portfolio-owner `
  --reason "업무 영향도 재평가"

py -m scripts.manage_assets history --asset-id <ASSET_ID>
```

`update`는 변경자와 사유를 반드시 받아
`asset_change_history`에 전후 값을 남깁니다.

## 6. 테스트

```powershell
py -m unittest discover -s .\tests -p "test_*.py" -v
py -m compileall -q .\asset_management .\scanner .\db .\scripts .\analysis .\verification .\api
py .\scripts\check_secrets.py
docker compose -f .\docker\docker-compose.yml config --quiet
git diff --check
```

외부 서비스나 브라우저에 의존하는 수동 실습 파일은 자동 단위
테스트와 구분합니다.

## 7. CVE 후보 분석

DB 없이 제공된 예시를 분석합니다. 파일 내 ID는 실습용이며 저장할 수 없습니다.

```powershell
py -m analysis.run_analysis --input .\examples\sample_ports.json
```

실제 DB 관찰값은 `--scan-id <스캔 ID>` 또는 `--asset-id <자산 UUID>`로
선택합니다. 기본은 미리보기이며 `--save`를 추가하면 후보와 근거가 저장됩니다.
전체 절차와 루프백 실습은 [서비스·CVE 매핑 실행 안내](docs/service_cve_mapping.md)에 있습니다.

규칙집은 공식 공지를 검토한 4개 CVE만 포함합니다. **미일치는 안전 판정이 아닙니다.**
설치 패키지·설정·패치 여부가 원격 읽기 전용 검사만으로 확인되지 않으면 추가 확인이 필요합니다.

## 8. CVE별 안전 검증

아래 `<VULN_ID>`, `<ASSET_ID>`, `<SCAN_ID>`는 실제 DB ID/UUID로 바꿉니다.

```powershell
py -m scripts.run_verification --vuln-id <VULN_ID> --scope-file .\config\scope.local.json --dry-run
py -m scripts.run_verification --vuln-id <VULN_ID> --scope-file .\config\scope.local.json
```

`--dry-run`은 DB 조회만 하며 대상 접속/DB write가 없습니다.
실행 시 승인 범위를 확인한 후 CVE ID별 읽기 전용 verifier를 선택합니다.
배너/버전이나 HTTP 200만으로 CONFIRMED를 만들지 않습니다.
연결·timeout 오류는 ERROR이며 증적·상태·이력을 한 transaction에 저장합니다.

## 9. 우선순위 평가

```powershell
py -m scripts.run_risk_assessment --asset-id <ASSET_ID>
py -m scripts.run_risk_assessment --asset-id <ASSET_ID> --save
```

`--vuln-id`, `--scan-id`, `--asset-id` 중 하나를 선택합니다.
기본 PREVIEW는 DB와 NVD/FIRST/CISA를 읽고 규칙 기반 action/priority를 출력합니다.
`--save`에서만 V5 평가 이력과 조건부 CVSS/EPSS summary를 저장합니다.
취약점 상태와 조치이력은 변경하지 않습니다. `vulns.risk`는 보존된 legacy 필드입니다.
API 오류는 0점/비취약 판정이 아니며 incomplete=true와 exit 1로 남습니다.
KEV 공식 미러로 복구된 원본 조회 오류도 기록하므로 결과 내용을 함께 확인합니다.

## 10. 저장된 결과 보고서

```powershell
py -m scripts.generate_report --asset-id <ASSET_ID> --output-dir .\reports --format both
py -m scripts.generate_report --scan-id <SCAN_ID> --format json
```

자산 UUID 또는 양의 scan ID 중 하나를 선택합니다. 기본은 `reports` 아래 JSON+PDF이며
`--format json|pdf|both`를 지원합니다. stdout JSON에서 출력 경로와 snapshot SHA-256을 확인합니다.
기존 `py -m api.generate_final_report`도 같은 옵션의 호환 진입점입니다. IP 위치 인수는 지원하지 않습니다.

보고서는 하나의 read-only consistent DB transaction으로 V5/V6 결과를 읽습니다.
스캔·분석·검증·위협정보 조회·Shodan 접속을 자동 실행하지 않습니다.
자산은 `p.last_scan_id = h.last_scan_id`, scan은 `p.last_scan_id = 선택한 scan ID`인 관찰만 사용합니다.
scan 선택은 `scan_assets`에 연결된 자산도 보여주지만 자산 metadata는 현재 값입니다.
과거 시점의 포트 상태를 완전히 재현하는 기능은 아닙니다.

최신 평가는 `last_assessed_at`, 동률일 때 `id` 순으로 선택합니다.
현재 상태/자산 정보와 일치하면 CURRENT, 다르면 STALE, 없으면 MISSING입니다.
STALE/MISSING의 요약 우선순위는 UNASSESSED이며 저장된 옛 평가는 이력으로 표시합니다.
CURRENT는 context 일치이며 외부 위협정보의 최신성이나 취약점 확정을 뜻하지 않습니다.

JSON과 PDF는 같은 snapshot을 사용하고 생성 시각을 제외한 내용 해시를 기록합니다.
증적·조치이력·규칙 근거·출처·누락 정보를 포함하며, 증적 JSON 파싱 실패는 개별 표시합니다.
관찰값/후보가 없는 것은 안전 판정이 아닙니다.
PDF는 ReportLab의 설치된 한글 폰트 또는 CJK CID font를 사용하며 외부 font를 다운로드하지 않습니다.
Windows에서는 설치된 맑은 고딕을 포함해 렌더링합니다. CJK fallback은 PDF 뷰어의 한글 글꼴 지원이 필요할 수 있습니다.
보고서에는 내부 자산과 증적 정보가 포함되며 `reports/`는 Git에서 제외됩니다.

전체 실행 흐름은 다음과 같습니다. 각 단계는 별도 명령으로 실행합니다.

**Scan → Analysis → Verification → Risk Assessment → Report**

## 문서

- `docs/architecture.md`: 전체 파이프라인, 설계 판단과 한계
- `docs/validation.md`: 자동 테스트, DB/E2E 검증 범위와 최종 체크리스트
- `docs/project_story.md`: 이력서·포트폴리오·면접 설명용 스토리
- `docs/database_schema.md`: DB V5 기본 구조와 관계 (`sql/migration_v6.sql`에서 AWS 확장)
- `docs/asset_management.md`: 자산관리·스코프·마이그레이션 상세 절차
- `docs/service_cve_mapping.md`: 서비스 식별·CVE 규칙·V4 적용·로컬 실습

## 11. AWS VPC 보안 아키텍처 확장 (V6)

기존 로컬/공인 IP 중심 실습에서 한 단계 확장해, AWS VPC 안에서 EC2 자산과 Security Group 구성을 읽기 전용으로 수집하고 승인된 private IP만 기존 스캐너로 진단할 수 있습니다.

핵심 원칙:

- AWS discovery != scan authorization
- AWS Access Key/Secret Key를 저장소나 `.env`에 저장하지 않음
- Scanner EC2는 IAM Instance Profile과 SSM Session Manager 사용
- Target EC2는 public IP 없음
- Target 8080은 Scanner Security Group에서만 허용
- SG 과다노출은 `cloud_configuration_findings`에 저장하고 CVE와 분리
- VPC Flow Logs는 네트워크 증적, CloudTrail Event History는 관리 API 증적으로 사용

구조와 제약은 `docs/aws_architecture.md`, 실제 검증 순서는 `docs/aws_validation.md`를 참고합니다.

### Terraform

```powershell
terraform -chdir=infra/aws/terraform init
terraform -chdir=infra/aws/terraform validate
terraform -chdir=infra/aws/terraform plan
terraform -chdir=infra/aws/terraform apply
```

기본값은 `enable_demo_misconfiguration=false`입니다.

### DB V6

V5 적용 후:

```powershell
Get-Content -Raw -Encoding UTF8 .\sql\migration_v6.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
Get-Content -Raw -Encoding UTF8 .\sql\verify_v6.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
```

환경에 맞는 MySQL 사용자/컨테이너 명령을 사용하고, 비밀번호를 shell history나 저장소에 남기지 않습니다.

### AWS inventory / SG review

먼저 DB write 없는 read-only preview:

```powershell
py -m scripts.aws_inventory --region ap-northeast-2 --vpc-id <VPC_ID>
py -m scripts.aws_security_review --region ap-northeast-2 --vpc-id <VPC_ID>
```

V6 DB에 저장할 때만 `--save`를 붙입니다.

```powershell
py -m scripts.aws_inventory --region ap-northeast-2 --vpc-id <VPC_ID> --save
py -m scripts.aws_security_review --region ap-northeast-2 --vpc-id <VPC_ID> --save
```

AWS API로 발견한 EC2는 자동 스캔하지 않습니다. 실제 진단은 기존 `ScopePolicy`를 통과해야 합니다.

```powershell
py -m scripts.run_scan scan `
  --target <TARGET_PRIVATE_IP> `
  --ports 22,8080 `
  --scope-file .\config\scope.aws.example.json `
  -sT -sV
```

V6 보고서는 CVE findings와 AWS configuration findings를 별도 항목으로 표시합니다. Security Group이 Internet-wide CIDR를 포함해도 라우팅/NACL/host firewall까지 계산하지 않으므로 실제 인터넷 도달성을 확정하지 않습니다.

현재 SG 설정 진단은 SSH(22), RDP(3389), MySQL(3306), PostgreSQL(5432), MongoDB(27017), FTP(21), Telnet(23), 전체 포트/프로토콜의 Internet-wide ingress를 별도 configuration finding으로 분류합니다.


## 보안 검증·증적·재점검 (MySQL V7)

기존 V6의 자산·CVE 후보·위험 평가와 함께 V7 검증 이력을 관리합니다. 실행 상태와 판정 상태를 분리하고 승인 Scope, 검사 시각, 대상, SHA-256을 보존합니다. FTP 익명 인증 허용과 DVWA SQLi는 각 설정/실습 검증이며 특정 CVE 확정을 뜻하지 않습니다. Nuclei 매칭은 `POTENTIAL`입니다. 증적이 없거나 실행에 실패한 항목을 안전하다고 판단하지 않습니다.

- FTP·HTTP·SSH 읽기 전용 검사, 비파괴 DVWA SQLi, 공식 배포본/실행 파일/버전/템플릿 무결성을 확인하는 Nuclei 실행
- 사용자 수집 EC2 증적의 원본 해시·대상·기존 스캔/포트·Scope 대조 후 V7 추가 저장 및 중복 방지
- 서로 다른 정상/EC2 스캔을 하나의 읽기 전용 DB 스냅샷에서 JSON/PDF로 출력
- 동일 서비스의 조치 전후 증적은 별도 이력으로 보존하며 시각·해시·변경 맥락을 함께 비교
- 별도 파라미터 SQL 앱은 DVWA와 독립 비교이며 DVWA 개선 완료로 표시하지 않음

### 검증 현황

Work의 전체 Python 회귀 테스트 **330개 통과**. GitHub Actions의 [기본 CI](.github/workflows/ci.yml)와 [격리 통합 검증](.github/workflows/lab_integration.yml)은 일회용 Docker/MySQL에서 V6→V7 기록 보존, 실제 FTP·SSH·HTTP·DVWA·Nuclei, HTTP/FTP 개선 후 재점검, JSON/PDF·무결성을 검사합니다. 최신 실행 결과와 보고서 아티팩트는 [Actions](https://github.com/LEESJ7934/infrastructure-security-scanner/actions)에서 확인합니다. CI의 `EC2_LAB`은 모의 환경 저장 라벨이며 실제 AWS 결과가 아닙니다.

사용자 EC2 실측(사용자가 2026-10-20 공유한 결과): FTP `230 Login successful`, SSH 비밀번호 인증 비활성, HTTP 보안 헤더 4종 누락, DVWA 정상 1행→우회 5행. 사용자 확인 기준 DVWA는 Windows MySQL V7의 scan 7/port 4에 `CONFIRMED` 저장됐고 증적 무결성 `MATCH`를 확인했습니다. Work가 사용자 DB를 직접 열어 확인한 것은 아닙니다.

**남은 사용자 확인:** FTP/HTTP/SSH의 실제 V7 추가 저장, 신규 로컬 정상 스캔, 기존 EC2 대상 Nuclei 실행, 실제 Windows 통합 JSON/PDF 생성. 기존 AWS 서비스의 개선은 수행하지 않았습니다. 운영 SSH·Security Group·기존 데이터·다크웹 컨테이너를 변경하지 않습니다. Draft PR #1을 유지하고 최종 Squash 병합은 별도 승인 후 진행합니다.

- [Day 15~17 Windows·EC2 증적 연결](docs/day15_17_work1.md)
- [Day 18~20 Nuclei·재점검·최종 보고서 실행](docs/day18_20_final.md)
- [검증 결과와 한계](docs/lab_verification.md) / [Docker 실습 구성](lab/README.md)
