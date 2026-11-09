# 선정 16개 개인 LAB 재점검 절차

최신 실측은 13/16이며 S-06/S-07/CA-09 3개가 NEEDS_REVIEW다. WEB/MySQL 6개는 새 Actions 워크플로에서 실제 자동 수행했다. 아래 수동 절차와 함께 최신 자동화·남은 조건은 [외부 LAB 후속 절차](kisa-2026-external-followup.md)를 참고한다. 아래 명령은 사용자가 실행할 절차이며 실행 결과가 아니다. 프로젝트 루트의 PowerShell과 기존 `.venv\Scripts\python.exe`를 전제로 한다. 출력은 새 시각별 디렉터리에 보관하며 기존 증적을 덮어쓰지 않는다. 운영 계정·자원 생성·정책 파괴는 포함하지 않는다.

## 공통 증적 디렉터리와 오프라인 기준 확인

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$evidence = Join-Path (Get-Location) "evidence\kisa-$stamp"
New-Item -ItemType Directory -Path $evidence -ErrorAction Stop | Out-Null
.\.venv\Scripts\python.exe -m scripts.review_kisa_2026
Copy-Item .\rules\kisa-2026-observation-template.json (Join-Path $evidence 'observations.json')
```

기본 출력은 16 NOT_TESTED다. 템플릿은 결과가 아니다. 실제 원시 파일, 제품 버전, 수집 시각, 검토 근거를 확보한 필드만 채운다. 이름이 같은 JSON 키를 중복 입력하거나 여러 자산 중 일부를 생략해 PASS로 만들 수 없다. 판정 출력은 저장 자료 비교일 뿐 실측 출처 인증이 아니다.

```powershell
.\.venv\Scripts\python.exe -m scripts.review_kisa_2026 --input (Join-Path $evidence 'observations.json') |
    Out-File -LiteralPath (Join-Path $evidence 'selected-offline-review.json') -Encoding utf8
Get-ChildItem -LiteralPath $evidence -File | Get-FileHash -Algorithm SHA256
```

원시 파일은 `.gitignore`의 `evidence/`에 비공개 보관한다. 인증정보·로그 개인정보를 검토한 뒤 필요한 요약만 공개한다. 해시와 출처 선언만으로 실제 장비 실행을 입증하지 않는다.

## Linux U-01/U-18

새 일회용 환경은 PR의 기존 KISA Replay Actions가 실행한다. 사용자 PC의 **현재 Replay 프로젝트에 보존할 상태가 없는지 먼저 확인**한 후에만 기존 조치 절차를 이용한다. 이번 추가 수집기는 lifecycle 변경을 하지 않는다.

```powershell
docker context show
docker compose -f .\lab\linux-mysql-retest\compose.replay.json ps
# 기존 문서 kisa-ciip-2025-selected-review.md의 before/after 구성 절차 사용
.\.venv\Scripts\python.exe -m scripts.run_linux_mysql_audit --execute --lab-profile replay --output (Join-Path $evidence 'linux-after.json')
.\.venv\Scripts\python.exe -m scripts.collect_kisa_linux_selected --report (Join-Path $evidence 'linux-after.json') --output (Join-Path $evidence 'linux-selected-after.json')
```

before에서도 별도 이름으로 같은 수집을 수행한다. `/etc/shadow` 파일 내용은 읽지 않는다. SSH 설정이 공식 단순 LAB 템플릿과 다르거나 Include/Match가 있으면 모든 주소 문맥을 충족했다고 추론하지 않는다. 원격 호스트 SSH는 콘솔·별도 관리계정을 확보한 후 변경하며, Docker exec는 실제 원격 로그인 성공 증적이 아니다.

## Windows W-02/W-04/W-08/W-64

**Windows Server 2022 standalone 격리 VM의 관리자 콘솔 안에서** 실행한다. 사용자 PC나 도메인 서버에서 실행하지 않는다. 수정되는 것은 현재 VM의 잠금 정책, Guest 비활성화, 로컬 방화벽 프로필 활성화다. 관리 접근에 영향이 있으므로 VM 콘솔을 확보하고 조치 전 JSON을 보관한다. 잠금·방화벽 원래 값은 조치 전 JSON으로 복구할 수 있으며, 자동 복구가 필요한 공유 VM에서는 일회용 복제 VM을 사용한다.

```powershell
# VM 안에서: 기존 프로젝트 파일과 쓰기 가능한 증적 디렉터리 준비
.\scripts\apply_windows_kisa_lab.ps1 -ExpectedComputerName $env:COMPUTERNAME -OutputPath 'C:\LabEvidence\before.json'
.\scripts\apply_windows_kisa_lab.ps1 -ExpectedComputerName $env:COMPUTERNAME -OutputPath 'C:\LabEvidence\after.json' -Apply -AcknowledgeIsolatedLab
# VM 밖으로 비공개 복사 후 프로젝트 Python 환경에서 비교
.\.venv\Scripts\python.exe -m scripts.adapt_kisa_windows_selected .\evidence\after.json
```

원본 before/after에는 Guest RID501, 유효 ActiveStore 방화벽 프로필, secedit 값과 수집 시각이 있다. 로컬 정책의 결과를 도메인 GPO 결과로 해석하지 않는다. 잠금 전후 정상 사용자의 실제 로그인·잠금 유발 시험은 별도이며 이번 자동 수집에 포함되지 않았다.

## WEB-04/07/16

기존 Docker LAB을 재사용한다. 아래 수집은 읽기 전용이며 컨테이너 생성·삭제·강제 재생성을 하지 않는다.

```powershell
docker compose -f .\lab\web-was-lab\compose.json ps
.\.venv\Scripts\python.exe -m scripts.run_web_was_audit --execute --output (Join-Path $evidence 'web-was.json') --pdf (Join-Path $evidence 'web-was.pdf')
```

기존 내부 8개 결과를 KISA 3개 PASS로 즉시 바꾸지 않는다. Nginx와 Tomcat **각각** 다음 증거가 필요하다.

- WEB-04: 전체 유효 location/servlet 인벤토리, `nginx -T`, Tomcat 전역·앱 `web.xml`의 listings 및 실제 목록이 가능한 디렉터리 요청 결과.
- WEB-07: 승인한 배포 루트의 전체 파일·디렉터리 목록, 파일별 필요성 검토. docs/examples와 샘플·매뉴얼·백업·테스트 경로의 파일 부재와 HTTP 부재를 모두 확인. 403만으로 삭제를 주장하지 않는다.
- WEB-16: 정상 및 404/오류 응답의 헤더·본문과 프록시·직접 backend 경로. 제품 사례 기반 LAB에서는 Nginx 제품명 단독을 허용하지만 버전/OS는 노출하지 않는다. 상위 기관 정책이 제품명도 금지한다면 별도 프로파일로 판단한다.

컨테이너의 고정 서비스 주소는 기존 `Probe.java`를 참고한다. 호스트에 공개 포트를 새로 열 필요가 없다. 필요한 조치만 before/after Dockerfile·설정에서 변경하고 일회용 별도 프로젝트에서 재현한다.

## MySQL D-02/04/10

기존 `scripts.run_linux_mysql_audit`를 재사용하되 다음 **전체** 읽기 전용 SQL 인벤토리를 추가로 수집한다. 프로젝트에 포함된 전용 MySQL 클라이언트 설정 파일을 사용하고 암호를 CLI 인수나 JSON에 넣지 않는다.

```sql
SELECT VERSION();
SELECT User, Host, account_locked FROM mysql.user;
SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.USER_PRIVILEGES;
SELECT USER, HOST, PRIV, WITH_GRANT_OPTION FROM mysql.global_grants;
SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST, WITH_ADMIN_OPTION FROM mysql.role_edges;
SELECT User, Host, Proxied_user, Proxied_host, With_grant FROM mysql.proxies_priv;
SELECT @@GLOBAL.mandatory_roles;
```

각 계정·관리권한의 필요성·인가 목록을 수동 검토하고 상속 역할을 재귀적으로 펼친다. 앱 1개의 SHOW GRANTS로 전체 D-04를 충족하지 않는다. 불필요 계정 삭제/잠금·권한 회수 전 사용처를 확인한다. D-10은 모든 계정 Host와 방화벽·컨테이너 네트워크 경계를 검토한 후, 지정 관리/앱 출발지에서 정상 연결, 다른 비인가 출발지에서 거부를 실제 시험한다. `Test-NetConnection <LAB_DB_IP> -Port 3306` 결과는 TCP 도달성이지 DB 인증 성공이 아님을 기록한다. 원격 root 부재만으로 PASS가 아니다.

## OPNsense S-06/S-07

기존 승인된 로컬 설정 파일과 수동 시험 자료가 있을 때 `scripts.run_opnsense_lab_audit --execute`를 재사용한다. 관리 HTTPS 인증서 검증을 우회하지 않는다. 설정 파일의 실제 값·API 키는 공개하지 않는다.

```powershell
.\.venv\Scripts\python.exe -m scripts.run_opnsense_lab_audit --help
# 승인된 관리경로/출발지에서만 실제 주소로 대체
Test-NetConnection <LAB_MANAGEMENT_IP> -Port 443
curl.exe --cacert <LAB_CA_FILE> -I https://<LAB_MANAGEMENT_HOST>/
```

인가/비인가 출발지에서 각 시험을 수행하고 대상 인터페이스, 포트, 시간대, 결과, 적용 PF 규칙과 일치하는 로그를 연결한다. 장비 콘솔의 `pfctl -sr`, `pfctl -vvsr`를 별도 원본으로 보관한다. TLS/SSH 협상과 인증서/호스트키를 확인하고 HTTP/Telnet 관리 노출을 별도 점검한다. 단순 API 응답이나 한 구간의 ping으로 관리면 전체를 입증하지 않는다. 관리 정책을 바꾸기 전 콘솔·설정 백업·복구 경로를 확보한다.

## AWS CA-07/09

이미 존재하는 독립 LAB만 사용한다. 스코프 JSON/대상 JSON에 승인 계정·리전·자원을 명시하고 기존 읽기 전용 수집기를 실행한다. 새 리소스 생성·운영 정책 변경은 이 명령에 포함되지 않는다.

```powershell
.\.venv\Scripts\python.exe -m scripts.run_aws_audit --validate-inputs --scope-json <LAB_SCOPE_JSON> --targets-json <LAB_TARGETS_JSON> --expected-account-id <LAB_ACCOUNT_ID> --allowed-region <LAB_REGION>
.\.venv\Scripts\python.exe -m scripts.run_aws_audit --live-collect --scope-json <LAB_SCOPE_JSON> --targets-json <LAB_TARGETS_JSON> --expected-account-id <LAB_ACCOUNT_ID> --allowed-region <LAB_REGION> --output-root $evidence
```

CA-07은 서브넷 의도·명시/기본 라우트 연결·IGW/NAT·IPv6·공인 주소·실제 자원 배치를 함께 검토한다. CA-09는 SG/NACL의 출발지·목적지·프로토콜·포트·방향·순서와 불필요 규칙을 검토하고 **진짜 날짜의 정기 검토 기록**을 축적한다. 한 번의 검토를 반복 운영 실적으로 꾸미지 않는다. CloudTrail 기존 FAIL이나 IAM 검토 필요는 이 두 항목의 결과로 덮어쓰지 않는다.

## 수집 후 마감

원본→정규화 관찰→판정→개선→같은 자산 재수집의 연결과 버전을 확인한다. 합성 자료는 SYNTHETIC으로 유지한다. 운영환경 예외는 근거와 검토 주체가 있어야 한다. 16개 모두 원시 출처를 검증한 PASS일 때에만 100%로 문서·JSON·PDF를 함께 갱신한다.
