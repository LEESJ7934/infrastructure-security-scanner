# AWS 보안 설정 읽기 전용 수집

이번 구현에서는 실제 AWS API를 호출하지 않았다. 실제 자격증명 생성·조회, AWS 리소스 변경, Terraform, Docker/VM 변경, commit/push를 수행하지 않았다. 모든 수집 검증은 합성 응답과 주입한 가짜 SDK client로 수행했다.

## 세 실행 경로

| 경로 | 옵션 | SDK/네트워크 |
|---|---|---|
| Offline | 기본 실행 또는 --input-json | SDK client 생성/네트워크 없음. 기존 동작 유지 |
| Mock Collection | --mock-collect --mock-json | 실제 수집 코드에 합성 응답을 주입. 실제 SDK/network 없음 |
| Live Collection | --live-collect | 예상 계정·리전·scope·targets 검증 후 명시적 읽기 전용 조회 |

`--dry-run`은 계속 오프라인 평가 전용이다. live/mock collection과 함께 사용하면 수집 전에 거부한다. `--live-collect`가 없는 상태에서 수집용 인자만 입력해도 연결하지 않는다.

## 추가·변경 구조

- `cloud_security/aws_live.py`: API allowlist, STS gate, 호출·재시도·시간·페이지 제한, 실제/가짜 client factory, P1 8개 수집.
- `scripts/aws_collection_run.py`: 실행별 새 디렉터리, 수집 JSON 보존, 공통 엔진 평가 및 JSON/PDF 생성.
- `scripts/run_aws_audit.py`: 기존 오프라인 분기를 유지하고 명시적 live/mock 분기를 추가.
- `cloud_security/aws_scope.py`: 명시적으로 열거한 AWS 관리형 IAM policy ARN만 추가 허용. 다른 계정의 역할/정책이나 wildcard 수집 범위를 일반 허용하지 않음.
- `cloud_security/aws_observations.py`: RegionalStatuses가 있는 수집 입력에서는 모든 허용 리전의 trail 상태도 평가.
- 기존 인벤토리의 SG 정규화, SG 분석기, Observation/AuditRule/evaluate(), 보고서 모델·PDF 도구를 계속 사용한다. 기존 인벤토리 client factory는 STS보다 먼저 EC2 client를 만들고 제한 설정이 다르므로 새 연결 경로에서 호출하지 않는다.

## 수집 API와 권한

다음 목록만 SDK request gateway에서 허용한다. 변경 API는 구현하지 않았다.

| 서비스 | 허용 API | 연결 항목 |
|---|---|---|
| STS | GetCallerIdentity | 모든 수집의 선행 계정/partition 확인 |
| IAM | GetAccountSummary | IAM-01, IAM-02 |
| IAM | GetRole, ListAttachedRolePolicies, ListRolePolicies, GetRolePolicy, GetPolicy, GetPolicyVersion | IAM-03 |
| EC2 | DescribeSecurityGroups | SG-01 |
| EC2 | DescribeVpcs, DescribeSubnets, DescribeRouteTables, DescribeInternetGateways, DescribeNetworkInterfaces | VPC-01 |
| EC2 | DescribeNetworkAcls | NACL-01 |
| CloudTrail | DescribeTrails, GetTrailStatus, GetEventSelectors | CT-01 |
| EC2 | DescribeFlowLogs | FL-01 |

`config/aws-audit-readonly-policy.example.json`은 가짜 계정/리소스의 **미적용 예시**이다. 기존 역할에 자동 부착하지 않는다. 실제 실행 전 소유자가 허용한 기존 역할/credential chain과 필요한 권한을 확인해야 한다. EC2 Describe처럼 리소스 수준 제한이 어려운 조회는 IAM Resource=*와 리전 조건을 사용하되 애플리케이션이 VPC/ID 범위를 추가 제한한다. IAM 역할·정책·trail 조회는 가능한 명시 ARN으로 제한한다. P1에서 로그 본문 조회 권한이나 S3 객체 읽기 권한은 필요하지 않다.

## 범위와 입력 파일

scope 형식은 앞 단계와 동일하다. `resources`에 실제 조회할 역할, 연결 정책, SG, VPC, subnet, route table, 필요한 IGW/ENI/NACL/Flow Log ID 및 목적지 log-group ARN을 명시한다. `arn:...:iam::aws:policy/...`도 실제로 필요한 ARN을 명시한 경우만 읽는다. 정책 버전 조회는 허용된 policy ARN의 현재 기본 버전만 수행한다.

새 targets 형식은 `tests/fixtures/aws_live/targets.json`을 참고한다.

```json
{
  "schema_version": 1,
  "vpcs": {"ap-northeast-2": "vpc-001"},
  "targets": {
    "IAM-01": {"region": "global", "resource_id": "123456789012"},
    "IAM-02": {"region": "global", "resource_id": "123456789012"},
    "IAM-03": {"region": "global", "resource_id": "arn:aws:iam::123456789012:role/phase2-lab"},
    "SG-01": {"region": "ap-northeast-2", "resource_id": "sg-001"},
    "VPC-01": {"region": "ap-northeast-2", "resource_id": "subnet-001"},
    "NACL-01": {"region": "ap-northeast-2", "resource_id": "acl-001"},
    "CT-01": {"region": "ap-northeast-2", "resource_id": "arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/phase2-lab"},
    "FL-01": {"region": "ap-northeast-2", "resource_id": "vpc-001"}
  }
}
```

예상 계정 인자는 scope의 계정과 같아야 하고, `--allowed-region` 집합은 scope 리전 목록과 같아야 한다. IAM은 global이며 VPC에 속한 것으로 취급하지 않는다. EC2 대상은 해당 리전의 명시 VPC에 속해야 한다. CloudTrail 대상의 리전은 ARN의 HomeRegion과 같아야 한다.

불필요한 리소스 목록을 모두 저장하지 않는다. 필터로 조회한 ENI/Flow Log가 명시된 ID 목록에 없으면 제외하고 부분 수집으로 표시한다. 범위 밖 계정·소유자·VPC·관련 리소스 응답은 해당 항목 ERROR로 남기고 원문은 저장하지 않는다. 같은 VPC라는 이유로 새로운 리소스를 자동 승인하지 않는다.

## STS 및 제한 정책

첫 읽기 API는 STS GetCallerIdentity다. 예상 계정/partition과 일치하기 전에는 IAM/EC2/CloudTrail client 조회를 허용하지 않는다. 불일치하면 즉시 중단하고 다른 계정 리소스 데이터를 읽지 않는다. 실제 계정이 다를 때 감사 파일에는 다른 계정 ID를 저장하지 않고 일치 실패만 기록한다.

기본 제한은 다음과 같다.

- 수집 API 최대 100회, API별 페이지 최대 10개, 재시도 최대 1회.
- SDK 자체 숨은 재시도는 `total_max_attempts=1`. 수집기 재시도도 호출 예산에 포함.
- 연결 3초, 응답 읽기 8초. 전체 수집 deadline 120초를 요청 전·후 확인.
- 재시도는 throttling/일시 장애/timeout만 수행. AccessDenied는 반복 시도하지 않음.
- 상한: 호출 256, 페이지 32, 재시도 2, 연결 10초, 읽기 30초, deadline 600초.
- TLS `verify=True`, 환경·공유 설정의 endpoint override 무시, HTTPS AWS endpoint 확인. TLS 우회 옵션 없음.

표준 credential chain/기존 IAM 역할만 사용한다. 키/토큰 인자나 credentials 파일을 만드는 코드가 없다. SDK의 인증 provider가 수행하는 SSO/AssumeRole/외부 credential_process 요청은 수집기의 리소스 API 호출 수와 별개다. IMDS timeout/시도는 제한하지만 외부 credential_process까지 강제 중단한다고 주장하지 않는다. 첫 실제 실행에는 이미 정상 로그인된 표준 인증 경로를 준비해야 한다.

## 완전성·오류·판정

- IAM IsTruncated/Marker와 EC2 NextToken을 구분해 페이지를 읽는다. 토큰 누락·반복·페이지 한도는 complete=false이다.
- 다음 페이지 AccessDenied, timeout, 호출 예산 초과는 ERROR이며 빈 정상 결과로 변환하지 않는다.
- 정책 목록이 불완전하거나 미허용 연결 policy ARN이 있으면 IAM-03은 PASS하지 않는다.
- subnet의 명시 route table이 없을 때만 해당 VPC의 main table을 조회한다. 연결 정보가 불확실하면 PASS하지 않는다.
- CloudTrail은 명시 ARN만 DescribeTrails로 조회하고, 허용 리전 각각 GetTrailStatus를 호출한다. selectors는 HomeRegion에서 조회한다. 조직 trail은 현재 승인 계정/리전에서 보이는 범위만 확인하며, 다른 계정의 조직 trail을 자동 승인하지 않는다.
- 필드 누락은 ERROR 또는 NEEDS_REVIEW이며 기본 양호 값으로 채우지 않는다. CloudTrail의 basic/advanced selector 중 API가 생략한 대안 목록은 다른 목록이 실제 존재할 때만 빈 목록으로 정규화한다.
- CloudWatch log-group ARN의 `:*` 표기만 정확한 허용 log-group ARN으로 정규화한다. 다른 그룹 wildcard 조회를 허용하는 의미가 아니다.
- 실제 네트워크 도달 가능성, 전체 IAM 유효 권한, 현재 로그 레코드 전달은 계속 별도 NOT_TESTED다.

## 실행별 증적

`--output-root` 아래에 UTC 시각+UUID의 새 디렉터리를 생성한다. 기존 파일을 덮어쓰지 않는다.

```text
<새 실행 디렉터리>/collection.json
<새 실행 디렉터리>/snapshot.json
<새 실행 디렉터리>/report.json
<새 실행 디렉터리>/report.pdf
<새 실행 디렉터리>/manifest.json
```

collection.json에는 예상/실제 계정 일치, 허용 리전, 요청 API·성공/고정 오류 코드·재시도·시각, API별 페이지 완전성, 진단별 요청 참조와 규칙 버전을 기록한다. credential, Authorization, 응답 원문, 요청의 비밀 header, opaque 페이지 토큰은 저장하지 않는다.

snapshot.json은 기존 오프라인 envelope와 같다. Mock origin은 synthetic, 실제 수집 origin은 aws_collected_snapshot이다. 수집 JSON을 먼저 보존하고 기존 엔진으로 평가한 JSON/PDF를 생성한다. STS 단계 실패 시 snapshot/진단 결과를 만들어 내지 않고 collection.json/failure.json만 기록한다. PDF 실패 시에도 이미 저장한 snapshot/report는 남는다.

manifest의 SHA-256은 파일 식별·보존용이며 독립 기대 해시나 출처 진위 인증이 아니다. 보고서의 독립 검증 여부는 false다. 여러 API 응답을 하나의 원자적 AWS snapshot으로 보장하지 않는다.

## A. 기존 오프라인 실행 — 그대로 사용

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_aws_audit --input-json .\tests\fixtures\aws_audit\pass.json --scope-json .\tests\fixtures\aws_audit\scope.json --dry-run
```

## B. Mock Collection — AWS 연결 없음

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_aws_audit --mock-collect --mock-json .\tests\fixtures\aws_live\mock_responses.json --scope-json .\tests\fixtures\aws_live\scope.json --targets-json .\tests\fixtures\aws_live\targets.json --expected-account-id 123456789012 --allowed-region ap-northeast-2 --output-root .\reports\phase2-aws-mock
```

합성 정상 시나리오는 19개 가짜 읽기 응답, PASS 8개, account_match=true, network_access_enabled=false를 생성한다. 실제 AWS 검증 완료로 표시하지 않는다.

## C. 실제 실행 전 사용자 확인 — 이번에는 미실행

프로젝트 루트 PowerShell에서 기존 인증 경로가 준비됐을 때 사용자가 수행할 읽기 전용 사전확인 명령이다. `--debug`를 사용하거나 출력에 자격증명을 포함하지 않는다.

```powershell
aws sts get-caller-identity --region ap-northeast-2 --query Account --output text
```

표시된 계정이 본인의 예상 계정과 같은지 확인한다. 이 명령을 Codex 작업에서 실행하지 않았다. 키 생성/저장이나 IAM 역할 생성 명령은 제공하지 않는다.

실제 scope/targets는 예제의 가짜 ID를 그대로 사용하지 말고 승인된 기존 리소스의 실제 ID로 작성한다. 개인 입력은 기존 Git 제외 규칙에 맞는 `config/scope.aws-collection.local.json`, `config/scope.aws-targets.local.json` 같은 이름을 사용한다. 이 파일들을 이번에 실제 계정 정보로 만들지 않았다.

확인 후의 최초 실제 수집 예시:

```powershell
$expected = '본인의12자리AWS계정ID'
.\.venv\Scripts\python.exe -B -m scripts.run_aws_audit --live-collect --scope-json .\config\scope.aws-collection.local.json --targets-json .\config\scope.aws-targets.local.json --expected-account-id $expected --allowed-region ap-northeast-2 --max-calls 80 --max-pages 5 --max-retries 1 --connect-timeout 3 --read-timeout 8 --max-seconds 120 --output-root .\reports\phase2-aws-live
```

실제 결과는 PASS 8개로 보장하지 않는다. 자격증명/권한/대상 ID/페이지/중앙 관리 문맥에 따라 ERROR나 NEEDS_REVIEW가 정상적으로 나올 수 있다. 계정 불일치라면 다른 조회 없이 중단해야 한다. 일부 API 성공 시 가능한 항목만 평가하고 실패 항목을 PASS로 바꾸지 않는다. `--allowed-region`은 여러 번 지정할 수 있으나 scope 목록과 정확히 일치해야 한다.

## 테스트와 남은 범위

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_aws_live tests.test_aws_audit
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
```

실제 SDK client 생성 없이 주입한 client와 합성 JSON으로 STS gate, 자격증명 없음, 부분 실패, 페이지·호출·timeout 제한, 범위 위반, URI-encoded 정책, 지역별 trail 상태, 원문 비출력, 기존 오프라인 호환성을 검증한다. SDK Config 생성은 로컬에서 검증했지만 실제 endpoint/권한/서비스 응답 연동은 다음 사용자 실행 단계다.

전체 IAM 유효 권한, 중앙 루트 관리의 조직 증명, cross-account/공유 VPC, 로그 본문 전달 확인, P2 규칙, 실제 패킷 통신 및 AWS LAB 생성은 이번 범위가 아니다. 모든 변경 API·Terraform 실행은 없다.

조회가 기존 EC2/EBS/공용 IP 비용을 없애지는 않는다. 이 코드는 EC2·trail·Flow Logs·log group을 생성하지 않으며 CloudTrail Lake/CloudWatch Insights/S3 로그 본문 조회도 하지 않는다. 기존 trail의 접근 이벤트 기록·저장, 기존 리소스와 인증 provider 이용 조건은 별도 확인한다. 요금은 실제 실행 전 [AWS CloudTrail 요금](https://aws.amazon.com/cloudtrail/pricing/), [CloudWatch 요금](https://aws.amazon.com/cloudwatch/pricing/)을 확인한다.

## 공식 API 문서

- [Botocore Config: timeout/retry/endpoint](https://docs.aws.amazon.com/botocore/latest/reference/config.html)
- [IAM GetRole 및 정책 문서 인코딩](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_role.html)
- [CloudTrail DescribeTrails 및 shadow/organization trail](https://docs.aws.amazon.com/boto3/latest/reference/services/cloudtrail/client/describe_trails.html)
- [VPC Flow Logs 조회](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/describe_flow_logs.html)

기존 Linux/MySQL Replay의 실제 FAIL→PASS 증적과 앞 단계 AWS 합성 자료는 그대로 보존한다.
