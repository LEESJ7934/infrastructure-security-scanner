# AWS 보안 설정 오프라인 진단

## 실행 범위

이 실행기는 **로컬 JSON만 읽는다**. AWS SDK client, STS 호출, credential chain 조회, AWS CLI, Terraform 또는 네트워크 접근 경로가 없다. `--execute` 옵션도 없다. 기본 실행은 준비 상태 NOT_TESTED이고, `--dry-run`은 오프라인 평가만 수행하며 출력 파일 옵션을 거부한다.

```powershell
Set-Location C:\Projects\infrastructure-security-scanner-clone
.\.venv\Scripts\python.exe -B -m scripts.run_aws_audit
.\.venv\Scripts\python.exe -B -m scripts.run_aws_audit --input-json .\tests\fixtures\aws_audit\pass.json --scope-json .\tests\fixtures\aws_audit\scope.json --dry-run
```

기존 `scripts/aws_inventory.py`, `scripts/aws_security_review.py`의 기본 AWS 조회 동작은 변경하지 않았다. 새 오프라인 실행기와 구분한다. 자격증명을 만들거나 `.aws/credentials`를 읽을 필요가 없다.

## 구현 및 재사용

- `cloud_security/aws_scope.py`: 예상 계정, partition, 리전, 서비스, 명시적 리소스 ID/ARN, 관련 리소스 참조를 검증한다. wildcard 수집 대상은 금지한다. IAM은 global 문맥, 나머지는 허용 리전 문맥으로 구분한다.
- `cloud_security/aws_observations.py`: 8개 순수 입력 해석 함수. 상태를 직접 반환하는 새 판정 엔진이 아니며 최소 사실값과 기준 충족 여부를 기존 엔진에 제공한다.
- 기존 `cloud_security/aws_inventory.py`의 `_normalize_sg()`와 `aws_sg_analyzer.py`의 `analyze_resource()`를 재사용한다. 실제 `create_live_clients()`/`collect_inventory()`는 호출하지 않는다.
- `config_audit/collectors/aws_security.py`: Observation → AuditRule → 기존 evaluate(), 보고서 모델 어댑터와 저장 결과 비교 구조.
- `config_audit/aws_report.py`: 기존 PDF 폰트/escaping/스타일을 재사용한다. 동일 평가 결과를 JSON/PDF로 표시한다.
- 기존 `OPEN/RESOLVED`, DB 저장, ScopePolicy 능동 스캔, Day5 보고서와 Linux/MySQL 증적은 변경하지 않는다.

## 파일 형식

공개 fixture는 가상의 식별자와 **합성 값**만 포함한다.

- `tests/fixtures/aws_audit/scope.json`: 예상 범위와 내부 LAB 기준.
- `tests/fixtures/aws_audit/pass.json`: PASS 예제 8개.
- `tests/fixtures/aws_audit/fail.json`: FAIL 예제 8개.

이 파일들은 AWS SDK 응답 전체를 그대로 저장한 덤프가 아니다. **API 결과 중 필요한 필드와 별도의 수집 문맥을 담는 버전 1 envelope**다. 기존 인벤토리 JSON에는 페이지 완전성/IAM/라우팅 등의 필수 정보가 없으므로, 이를 자동으로 완전한 8개 진단 입력으로 간주하지 않는다.

최상위 필드:

```json
{
  "schema_version": 1,
  "origin": "synthetic",
  "account_id": "123456789012",
  "partition": "aws",
  "collected_at": "2026-01-01T00:01:00Z",
  "sections": {
    "IAM-01": {
      "service": "iam",
      "region": "global",
      "resource_id": "123456789012",
      "state": "COLLECTED",
      "pagination": {"complete": true, "pages": 1, "next_token_present": false},
      "collected_at": "2026-01-01T00:01:00Z",
      "data": {"SummaryMap": {"AccountAccessKeysPresent": 0}}
    }
  }
}
```

`origin`은 `synthetic` 또는 `aws_collected_snapshot`이다. 후자는 사용자가 실제 AWS에서 저장한 자료라는 **입력 선언**이며 수집 출처의 진위 인증이 아니다. 합성 테스트 결과를 실제 AWS 결과로 저장하지 않는다. 실제 수집 자료 예제를 이번 단계에서 만들어 내지 않았다.

`COLLECTED`에는 pagination이 필수다. `complete=false` 또는 `next_token_present=true`이면 해당 항목은 NEEDS_REVIEW이며 PASS하지 않는다. 누락된 section/NOT_TESTED는 NOT_TESTED, 필수 설정 필드 누락은 NEEDS_REVIEW, 오류 응답/잘못된 타입은 ERROR다. 계정·리전·서비스·리소스 범위 불일치는 입력 전체를 차단한다.

ERROR section은 `data=null`, 고정 `error_code`만 사용한다. AccessDenied, AccessDeniedException, UnauthorizedOperation, ExpiredToken, Throttling, RequestLimitExceeded, Timeout, ParseError, ServiceUnavailable를 지원한다. 원본 오류 본문은 저장하거나 출력하지 않는다.

`CentralizedRootManagement`, `PolicySetComplete`, `RouteTableAssociationResolved`, pagination은 AWS 응답 필드라고 주장하지 않는 별도 수집 문맥이다. 향후 수집기가 실제 조회 결과를 근거로 채워야 하며, 없으면 안전한 값으로 추정하지 않는다.

## 8개 진단 기준

규칙 버전 `AWS-LAB-OFFLINE-0.1`, 프로젝트 내부 개인 LAB 기준이며 KISA/고객사 인증 기준이 아니다.

| 항목 | PASS | FAIL | 검토·미검증 조건 |
|---|---|---|---|
| IAM-01 | SummaryMap.AccountAccessKeysPresent=0 | 1 | 필드 없음 NEEDS_REVIEW |
| IAM-02 | 루트 MFA 활성 | 루트 자격증명 존재 + MFA 없음 | 자격증명 없음·중앙 관리 불명확 NEEDS_REVIEW. 중앙 관리 제거 문맥 확인 시 NOT_APPLICABLE |
| IAM-03 | 지원하는 Allow 선언이 명시한 LAB action/resource 범위 내 | 명확한 과도한 Allow | 조건/NotAction/NotResource, 정책 누락·불완전 수집 NEEDS_REVIEW |
| SG-01 | 지원하는 전체 입력에서 명시적 /0 관리·DB 인바운드 없음 | 기존 AWS-SG-001~008 발견 | prefix list/미지원 프로토콜 NEEDS_REVIEW |
| VPC-01 | public IP 자동 할당 없음, 직접 IGW 경로/공용 ENI 주소 없음 | 해당 설정 존재 | 연결 route table 미확정, 빈 경로, 미지원/비활성 경로 NEEDS_REVIEW |
| NACL-01 | 선언한 TCP 행렬에서 비인가 ingress 차단 및 허용 시 요청·반환 모두 허용 | 앞선 Allow 또는 허용 시험의 반환 차단 | 방향별 판단 불가 NEEDS_REVIEW, 중복 규칙 번호 ERROR |
| CT-01 | 로깅 활성·multi-region/global·관리 read/write 포함·보고된 전달 오류 없음 | 확인된 요구 설정 미충족/요구 trail 없음 | advanced selectors, 빈/누락 selector 정보 NEEDS_REVIEW |
| FL-01 | 정확한 대상 VPC의 ALL/ACTIVE Flow Logs | 미적용, ACCEPT/REJECT 전용 등 기준 미충족, 명시적 전달 실패 | PENDING·미지원 목적지 NEEDS_REVIEW |

모든 규칙은 미실행 NOT_TESTED, 오류 응답 ERROR를 공통 적용한다. IAM-02를 제외하고 적용 제외를 추정하지 않는다.

IAM `Resource:"*"`는 `ec2:DescribeInstances`, `DescribeSecurityGroups`, `DescribeVpcs`, `DescribeNetworkInterfaces`의 명시적 허용 action일 때 정당한 사용으로 처리한다. 모든 wildcard를 취약으로 보지 않는다. S3 GetObject의 범위 초과는 별도로 판정한다. 이는 정책 **선언 범위** 점검이며 SCP/boundary/session/resource policy를 포함한 전체 유효 권한 증명이 아니다. Deny가 있다는 이유로 광범위 Allow 선언을 자동으로 지우지 않는다.

SG PASS는 정규화된 명시적 /0 규칙 범위다. 여러 CIDR의 합집합이나 SG 참조 뒤의 전체 도달 가능성을 증명하지 않는다. 기존 전체 포트 AWS-SG-006 탐지가 다른 포트 발견사항을 대표해도 FAIL이 유지된다.

NACL은 낮은 번호 우선으로 TCP 요청 ingress와 반환 egress를 계산한다. `BLOCK` 기준은 비인가 요청 ingress 차단이며, 반환만 막혔다고 안전한 ingress로 보지 않는다. `ALLOW` 기준은 양방향 허용이다. 실제 패킷 통신과 전체 트래픽 공간 검증은 NOT_TESTED다.

CloudTrail과 Flow Logs의 설정 PASS가 로그 전달 성공이 아니다. `delivery_verification=NOT_TESTED`, 실제 로그 레코드 검증 NOT_TESTED를 별도 기록한다. 현재 Flow Logs는 VPC 자체의 ALL/ACTIVE와 CloudWatch Logs 목적지 형식을 우선 지원한다. subnet/ENI 전체를 합산한 VPC 커버리지, S3/Firehose 목적지는 후속 범위다. 조직/다른 계정 trail을 임의로 같은 계정에 포함하지 않는다.

## JSON/PDF 생성 — 전부 오프라인

프로젝트 루트 PowerShell. 기존 파일은 덮어쓰지 않으며 경로가 이미 있으면 새 실행 디렉터리를 사용한다.

```powershell
$run = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = ".\reports\phase2-aws\$run"
New-Item -ItemType Directory -Path $out | Out-Null
.\.venv\Scripts\python.exe -B -m scripts.run_aws_audit --input-json .\tests\fixtures\aws_audit\fail.json --scope-json .\tests\fixtures\aws_audit\scope.json --output "$out\before.json" --pdf "$out\before.pdf"
.\.venv\Scripts\python.exe -B -m scripts.run_aws_audit --input-json .\tests\fixtures\aws_audit\pass.json --scope-json .\tests\fixtures\aws_audit\scope.json --baseline-json "$out\before.json" --output "$out\after.json" --pdf "$out\after.pdf"
```

합성 before는 FAIL 8개, after는 PASS 8개, 기록상 개선 관찰은 8건이다. 실제 AWS 개선 완료 여부는 false로 유지한다. PDF의 항목별 판정은 동일한 JSON 평가 결과에서 출력하고, 입력 텍스트를 HTML로 해석하지 않는다.

JSON에는 자산/진단/규칙 ID, 상태, 최소 관찰값, 사유, 위험 설명, 개선 권고, 수집 상태·완전성·수집 시각, 분석 시각, 입력 파일 해시와 scope 해시를 기록한다. 원본 정책/응답/로그/자격증명 전체를 복사하지 않는다. 자동·수동 채널은 합치지 않고 이번 manual은 None이다.

## 무결성과 비교

SHA-256은 실제 파일에서 계산한다. 독립 기대 해시가 없으면 `NOT_VERIFIED`, `independently_verified=false`이다. 사용자가 `--expected-sha256`을 지정하면 일치 여부를 `MATCH_DECLARED_HASH`로 기록하되 출처 인증·독립 검증 완료로 승격하지 않는다. 불일치하면 입력을 거부한다. 현재 해시를 자동으로 기대 해시에 재사용하지 않는다.

저장된 결과 비교는 account/partition/origin/scope 해시/규칙 버전, asset/check/scope/method와 수집 시각 순서를 확인한다. 중복 결과 중 하나를 임의로 고르지 않는다. ERROR→PASS는 UNVERIFIABLE이며 개선으로 처리하지 않는다. 비교는 원본 결과를 수정하지 않으며 실제 조치의 인과관계를 확정하지 않는다.

기존 Day5의 `normalize()`와 증적 인덱스는 Day2~4/고정 경로용이며 이번에 변경하지 않았다. `as_snapshot()`/`common_snapshot()`은 ReportResult/SourceSnapshot을 반환하는 연결 지점이다. AWS의 day=0과 경로를 기존 인덱스에 그대로 전달할 수 있다고 주장하지 않는다. 전체 통합 증적 인덱스 연결은 후속 단계다.

## 테스트

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_aws_audit
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
```

8개 항목 각각 PASS/FAIL/필수 정보 누락/AccessDenied/부분 수집/미실행을 합성 fixture로 검증한다. 추가로 범위 불일치, IAM wildcard, NACL 순서·반환 통신, CloudTrail/Flow Logs 설정과 전달 구분, 해시 변조, JSON/PDF 일치, SDK/socket/subprocess 차단을 테스트한다. AWS 자격증명은 필요하지 않다.

## 다음 단계 실행 계획

- 실제 AWS 연결은 이번에 구현하지 않았다. 별도 명시적 실행 경로, 읽기 전용 API allowlist, 표준 credential chain/IAM 역할, 최초 STS 예상 계정 대조가 필요하다.
- API별 페이지·권한·부분 성공을 실제 응답으로 검증하고, 수집 완전성을 추정하지 않고 기록한다.
- 설정 개선은 별도 사용자 작업 단계로 분리하고 수집기에 변경 API를 추가하지 않는다.
- SG-02/CT-02/FL-02/FL-03은 예약 ID만 제공한다. 규칙 registry로 확장할 수 있으나 이번 8개 결과에 임의의 PASS를 추가하지 않는다.
- 여러 리소스 일괄 처리, 전체 IAM 유효 권한, CloudTrail advanced selectors, 실제 로그 전달, 실제 도달 가능성, Terraform LAB와 DB 확장은 후속 범위다.

이번 단계에서는 AWS 리소스·기존 증적·DB·Docker·VM을 변경하지 않는다. 개인 증적, 자격증명, Terraform state/plan은 공개 Git에 포함하지 않는다.
