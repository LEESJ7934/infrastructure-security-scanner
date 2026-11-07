# AWS scope v2 — 리소스 부재와 기준 미확정 처리

v1 오프라인 입력과 기존 판정 엔진을 유지하고, 실제 수집용 v2 scope/targets를 추가했다. 이 작업에서는 실제 AWS API, Terraform, 리소스 변경, commit/push를 수행하지 않았다.

## 원인과 수정

기존 AwsScope.from_dict()는 빈 IAM 기준, 빈 NACL 행렬, 빈 CloudTrail/logs 리소스 목록을 모두 거부했다. validate_targets()는 CT-01에 반드시 Trail ARN을 요구하고 VPC-01은 서브넷만 허용했다. 따라서 리소스가 없는 환경과 기준이 미확정인 환경을 정상 입력으로 표현할 수 없었다.

v2에서는 다음을 분리한다.

- 수집 범위: 계정, partition, 리전, 명시 리소스 목록. IAM 역할과 연결 정책 ARN은 계속 명시한다.
- 정책 기준: policy.criteria_version, iam_role_criteria_confirmed, internal_subnet_ids, nacl_criteria_confirmed, trail_required, flow_required, flow_scope.
- 없음: 성공한 완전한 API 조회에서 빈 목록을 받은 경우.
- 미확인: 정책 기준 또는 자산 용도가 미확정인 경우. NEEDS_REVIEW.
- 실패: AccessDenied, 응답 파싱 실패, 호출/시간 제한. ERROR.
- 부분 수집: 토큰 반복/페이지 제한, 범위 밖 결과 제외 등. NEEDS_REVIEW이며 PASS 금지.

schema_version은 scope와 targets 모두 2로 설정한다. schema_version=1은 기존 엄격한 형식을 계속 사용한다. v2 규칙 버전은 AWS-LAB-COLLECTION-0.2이다.

## P1 처리

| 항목 | v2 동작 |
|---|---|
| IAM-01/02 | 계정 요약의 실제 필수 값을 기존 엔진으로 평가. 중앙 루트 관리 문맥을 추정하지 않음 |
| IAM-03 | 명시한 역할·연결/인라인 정책·기본 버전 문서 수집. Action, Resource star, Condition 존재를 분석. 허용 기준 미확정은 NEEDS_REVIEW. Resource:* 하나만으로 FAIL하지 않음. 전체 유효 권한/SCP/경계 평가 아님 |
| SG-01 | 명시 SG 하나의 설정을 평가. 범위에 등록한 SG를 모두 자동 평가하는 것은 아님. ENI 연결 부재는 설정 FAIL을 PASS로 바꾸는 근거가 아님 |
| VPC-01 | resource_id를 지정 VPC ID로 설정. 허용 목록에 있는 서브넷의 연결/메인 라우팅, IGW/NAT 등 경로 종류, 자동 퍼블릭 IP 및 허용된 ENI 주소 설정 분석. 내부용 서브넷 미확정이면 NEEDS_REVIEW. 기본 VPC를 임의로 내부용으로 분류하지 않음 |
| NACL-01 | 명시 행렬에 대해 규칙 번호가 낮은 첫 일치 규칙, Inbound 요청과 Outbound 반환 방향을 분석. 증적/방향 누락은 PASS 금지 |
| CT-01 | resource_id에 예상 계정 ID를 사용해 계정·리전 목록 조회. includeShadowTrails=true. 완전한 빈 목록 + trail_required=true이면 해당 리전의 지속 기록 Trail 기준 FAIL. Event History와 구분 |
| FL-01 | resource_id는 지정 VPC. 명시된 VPC/Subnet/ENI ID만 resource-id 필터로 조회. 필수 기준은 VPC ALL 트래픽 설정이며 자식 리소스 설정만으로 전체 VPC PASS 금지. 완전한 빈 목록 + flow_required=true이면 FAIL |

CloudTrail 발견은 예상 계정과 허용 리전의 trail ARN만 후속 조회한다. 다른 계정의 조직 Trail 또는 허용 범위 밖 HomeRegion은 원문을 저장하지 않고 수집 미완료로 표시한다. AWS 계정 전체/조직 전체의 미설정을 확정하는 결과가 아니다. DescribeTrails는 페이지 토큰이 없는 API이나 예상 밖 토큰이 반환되면 완전한 빈 목록으로 처리하지 않는다.

FlowLog ID와 로그 그룹이 미리 존재할 필요는 없다. 신규 발견 FlowLog는 ResourceId가 정확히 요청한 부모 범위에 속할 때만 저장한다. 임의 FlowLog ID 조회 권한으로 확장하지 않는다. 미승인 로그 목적지 ARN은 내보내지 않고 목적지 설정 존재 여부만 기록한다. 설정 PASS는 로그 본문 전달 확인이 아니다. 지원하는 목적지 유형은 CloudWatch Logs/S3/Firehose이며 실제 목적지 접근성은 검증하지 않는다.

## 개인 로컬 설정

config/scope.aws-collection.local.json과 config/scope.aws-targets.local.json은 Git 제외 대상이며 실 계정 정보를 공개 fixture에 복사하지 않는다. 이번에 반영한 역할 ARN 및 AWS 관리형 연결 정책은 사용자 과거 AWS CLI 출력에 근거했다. 실제 정책 문서나 현재 환경을 이번 작업에서 재조회한 것이 아니다. 원본 JSON/PDF 증적 대신 설정 파일만 수정했으며 수정 전 설정을 별도 로컬 백업했다.

현재 로컬 policy는 내부 역할 기준 미확정(false), 내부 서브넷 목록 빈 값, 지속 Trail 필수, VPC ALL Flow Logs 필수이다. NACL LAB 기준은 문서용 주소 198.51.100.10에서 TCP 22/23/3389 요청을 Inbound에서 차단하고 반환 포트 55000의 Outbound 규칙도 확인하는 유한한 시험 행렬이다. 이 주소는 실제 공격 출발지나 실행한 패킷 시험 증적이 아니다. 모든 IP/포트/ephemeral 포트 공간에 대한 증명도 아니다. 이 설정은 이번 요청에 따라 정의한 내부 LAB 기준이며 KISA 또는 조직 승인 기준이 아니다.

VPC topology는 실제 IGW attachment의 별도 조회 없이 라우트의 gateway 종류를 분석한다. 허용 목록 밖 ENI는 저장하지 않고 부분 수집으로 남긴다. 추가 정책·라우팅·ENI가 발견되어도 자동으로 범위를 승인하지 않는다.

## 오프라인 사전검증 (AWS 연결 없음)

프로젝트 루트 PowerShell:

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_aws_audit `
  --validate-inputs `
  --scope-json .\config\scope.aws-collection.local.json `
  --targets-json .\config\scope.aws-targets.local.json `
  --expected-account-id $expected `
  --allowed-region ap-northeast-2
```

$expected에는 사용자가 확인한 본인의 12자리 계정 ID를 설정한다. 예상 출력은 status=VALID, network_access=false, scope_schema_version=2, targets=8이다. VALID는 입력 정합성이며 실 AWS 수집/진단 성공이 아니다. 이 경로는 SDK factory를 호출하지 않는다.

## 향후 사용자 실행 전용 (이번 작업에서는 미실행)

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_aws_audit `
  --live-collect `
  --scope-json .\config\scope.aws-collection.local.json `
  --targets-json .\config\scope.aws-targets.local.json `
  --expected-account-id $expected `
  --allowed-region ap-northeast-2 `
  --max-calls 80 --max-pages 5 --max-retries 1 `
  --connect-timeout 3 --read-timeout 8 --max-seconds 120 `
  --output-root .\reports\phase2-aws-live
```

실제 AWS 조회 권한과 인증 경로는 따로 확인해야 한다. AmazonSSMManagedInstanceCore가 진단 수집용 권한을 제공한다고 가정하지 않는다. 대상 역할의 정책을 변경/부착하지 않는다. 기존 읽기 전용 정책 예시는 config/aws-audit-readonly-policy.example.json이며 사용자 역할/계정에 맞는 GetRole/GetPolicyVersion/DescribeTrails/GetTrailStatus/GetEventSelectors 권한이 필요하다. 정책 예시는 자동 적용하지 않는다.

기존 출력 폴더가 있어도 실행별 UTC+UUID 새 하위 폴더만 만든다. STS 불일치는 후속 조회 전 중단한다. 자격증명은 표준 credential chain, TLS 검증/호출/페이지/시간 제한은 기존대로 유지한다.

## 테스트

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_aws_scope_v2 tests.test_aws_live tests.test_aws_audit
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
```

모든 신규 테스트는 합성 자료와 Mock만 사용한다. socket 연결을 차단하고 validate/mock CLI에서 실제 factory 사용을 금지한다. 실 AWS 설정 변경이나 실제 PASS 결과를 생성하지 않는다.

공식 API 근거:
- https://docs.aws.amazon.com/boto3/latest/reference/services/cloudtrail/client/describe_trails.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/describe_flow_logs.html
