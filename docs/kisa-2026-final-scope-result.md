# KISA 2026 선정 범위 실제 LAB 재점검 결과

**선정 16개 중 실측 PASS 13개(81.25%), NEEDS_REVIEW 3개. 100% 목표는 아직 미달성이다.** NOT_TESTED 0은 모두 전체 검증됐다는 뜻이 아니다. OPNsense 2개와 CA-09는 실제 부분 수집 후 미충족 조건이 남아 검토 필요다.

## 기준·범위·원본 보존

공식 PDF 873쪽의 ID·정식 명칭·페이지·권고 기준과 분모 16개는 [동결 범위](kisa-2026-selection-freeze.md)대로 유지했다. 웹 항목은 Nginx와 Tomcat 모두 충족해야 1개 PASS다. VTY·Linux 방화벽을 혼동하지 않으며 고객사 수행·공식 인증·KISA 전체 준수를 주장하지 않는다.

기존 6개 PASS 행의 관찰값·수집 시각·실행/아티팩트 링크는 변경하지 않았다. [6/16 원본 JSON](history/kisa-2026-6of16.json)과 [당시 결과 문서](history/kisa-2026-6of16.md)를 보존했다. 최신 [구조화 대장](kisa-2026-final-scope-result.json)은 서로 다른 환경·시각의 검토된 증적 대장이며 동시 스냅샷이 아니다. 저장자료 판정의 PASS나 SYNTHETIC 테스트를 VERIFIED_LAB으로 승격하지 않는다.

## 공식 항목별 결과

| ID | 자산 | 최종 | 실제 수집 시각(원문 UTC) | 핵심 근거/한계 |
|---|---|---|---|---|
| U-01 | linux | PASS | 2026-11-09T07:38:26.600807+00:00 | 기존 단순 SSH 템플릿 yes→no, 해당 컨테이너 범위 |
| U-18 | linux | PASS | 2026-11-09T07:38:26.600807+00:00 | 기존 root 정규 파일 0666→0400, 링크 아님 |
| W-02 | windows | PASS | 2026-11-09T07:37:42.9252312+00:00 | 기존 RID501 비활성 재확인 |
| W-04 | windows | PASS | 2026-11-09T07:37:42.9252312+00:00 | 기존 secedit 임계값 10→5 |
| W-08 | windows | PASS | 2026-11-09T07:37:42.9252312+00:00 | 기존 secedit 잠금/초기화 10/10→60/60분 |
| W-64 | windows | PASS | 2026-11-09T07:37:42.9252312+00:00 | 기존 ActiveStore 3개 프로필 활성 재확인 |
| WEB-04 | nginx, tomcat | PASS | 2026-11-09T08:33:05.385990+00:00 | 두 제품의 설정·실제 파일 목록·디렉터리 HTTP, FAIL→PASS |
| WEB-07 | nginx, tomcat | PASS | 2026-11-09T08:33:05.385990+00:00 | 두 제품의 실제 배포 루트 불필요 파일 제거 및 HTTP 404 |
| WEB-16 | nginx, tomcat | PASS | 2026-11-09T08:33:05.385990+00:00 | 두 제품 정상 200/오류 404 응답·헤더와 유효 설정 |
| D-02 | mysql | PASS | 2026-11-09T08:32:48.003334+00:00 | 전체 계정 10→7, 용도 명세와 시스템/역할 잠금 확인 |
| D-04 | mysql | PASS | 2026-11-09T08:32:48.003334+00:00 | 정적/동적 권한·역할/프록시 상속 확장, 불필요 SUPER 제거 |
| D-10 | mysql | PASS | 2026-11-09T08:32:48.003334+00:00 | 허용 IP TCP·실제 SELECT 성공; 비허용 IP TCP timeout 및 nft drop counter |
| S-06 | opnsense | NEEDS_REVIEW | 2026-11-09T08:35:43.794108+00:00 | 인증된 인터페이스 API 성공, 규칙/ID API 403; 별도 비인가 출발지 미검증 |
| S-07 | opnsense | NEEDS_REVIEW | 2026-11-09T08:35:43.794108+00:00 | CA/IP SAN 검증된 TLS 1.3, HTTP→HTTPS 301; 관리 채널 전체 설정 미확보 |
| CA-07 | aws | PASS | 2026-11-09T08:35:38.691178+00:00 | 독립 내부전용 VPC 전체 조회: 서브넷 1, ENI 0, 공인 IP/직접 IGW 경로 없음 |
| CA-09 | aws | NEEDS_REVIEW | 2026-11-09T08:35:38.691178+00:00 | SG 2/NACL 2 전체 조회; 규칙별 필요성 승인·정기 검토 이력 미입증 |

## WEB/MySQL 실제 개선·재점검

[성공 실행 42586652707](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/42586652707)에서 별도 WEB/MySQL job이 모두 성공했다. 각 그룹의 before FAIL 3→after PASS 3을 assertion으로 검증했고, 다른 13개를 해당 job에서 PASS로 만들지 않았다.

- [WEB 원시 아티팩트 13659516646](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/42586652707/artifacts/13659516646): ZIP SHA-256 `e42012cb85f73e5dad6db999541dae9a8d36be9a51711b443f9c6d7564710d2a`. Nginx/Tomcat 실제 파일 목록·정상/오류/목록/백업/docs/examples HTTP 상태·헤더·본문과 설정이 있다. after 배포 파일은 Nginx 1개, Tomcat 3개로 고정된 필요 파일 목록과 일치했다. 범위는 해당 일회용 LAB의 모든 배포 루트/컨텍스트이며 운영 사이트 전체가 아니다.
- [MySQL 원시 아티팩트 13659527937](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/42586652707/artifacts/13659527937): ZIP SHA-256 `42691c89752886ab3d1811d749563e51268de1591c732ecc38cc6ee60ccf7dcc`. 계정·권한 SQL 결과와 쿼리, 역할/프록시 그래프, 서로 다른 실제 클라이언트, 전체 nft JSON을 보존했다. 허용 출발지 `172.30.96.20`은 TCP와 테이블 SELECT 성공, 비인가 `.30`은 exit 124 timeout이며 대응 drop counter가 증가했다. MySQL Host도 지정 IP로 제한했다. 암호·해시는 수집하지 않았다.

전후 수집은 같은 일회용 프로젝트의 자산·버전에서 수행했다. 웹은 취약/개선 이미지를 재구성했고, MySQL은 실행 중인 서버의 불필요 계정·권한을 개선하고 해당 네임스페이스 ingress를 제한했다. 기존 사용자 컨테이너·호스트 방화벽·원본 자료는 변경하지 않았다. 초기 수집/판정 오류가 있던 실행은 성공 증거로 사용하지 않았고 수정 후 실제 재실행했다.

## AWS 실제 조회와 판단 한계

CLI 로그인 갱신 후 STS가 기존 승인 계정과 일치하는 것을 확인했다. 기본 VPC 스코프와 과거 독립 LAB 스코프를 구분하고 **독립 LAB**에서 최종 CA-07/09 수집을 수행했다. 새 리소스 생성, Terraform apply, IAM/SG/NACL/라우트 수정은 하지 않았다.

CA-07은 기존 독립 **private-only VPC** 범위의 PASS다. 전체 subnet/route association/ENI를 조회했고, 내부 서브넷 1개·라우트 테이블 2개·ENI 0개를 확인했다. 내부 자원과 공개 자원 혼용이 없고 자동 공인 IP와 인터넷 직접 경로가 없다. 공개 workload·NAT·실제 패킷 통신·계정 전체 VPC 검증은 아니다. 이전 공식 CA-07 before 측정이 없어 FAIL→PASS로 표현하지 않는다.

CA-09는 실제 SG 2개/NACL 2개(기본 정책 포함)를 조회하고 현재 기술 검토 기록을 남겼다. **2026-11-06의 before/after 구성 자료나 이번 세션의 반복 재수집을 정기 검토 회차로 바꾸지 않았다.** 규칙별 목적 승인과 주기적 검토 이력이 입증되지 않아 NEEDS_REVIEW다. 기존 CT-01 FAIL과 IAM-03 NEEDS_REVIEW는 별도 내부 범위에서 그대로 보존된다.

AWS 원시는 개인 계정·자산 식별자를 포함하므로 Git에 올리지 않았다. 사용자 전달물 `KISA-2026-AWS-live.zip`에 원시 metadata·실제 요청 ID/시각·관찰·판정·정책 검토 기록·해시 manifest를 비공개 보존한다. 해시만으로 출처를 인증하지 않으며 이번 실행에서는 실제 TLS SDK 호출과 STS 소유자 대조를 수행했다.

## OPNsense 실제 연결과 미완료 원인

사용자가 기존 VM을 시작한 후, 보존된 LAB CA로 **IP SAN과 인증서 체인이 검증된 TLS 1.3** 연결을 실제 확인했다. HTTP는 비밀번호 로그인 폼 없이 HTTPS로 301 리디렉션했다. 사용자가 지정한 기존 non-root auditor API 키는 메모리에서만 사용했고 키/Secret은 로그·Git·결과에 내보내지 않았다. 현재 인터페이스 API는 성공했지만 규칙/규칙 ID API는 **403 api_forbidden**이었다.

S-06은 전체 유효 관리 접근 정책·PF 규칙과 독립 비인가 출발지 시험의 상관 증거가 부족하다. S-07은 확인된 LAN HTTPS 외 관리 서비스/인터페이스·평문 채널 전체의 설정 인벤토리가 부족하다. 따라서 둘 다 NEEDS_REVIEW이며 API 403은 원시 오류 그대로 남긴다. TCP timeout만으로 서비스가 꺼졌거나 접근통제가 완성됐다고 하지 않았다. 장비 설정·키·API 권한은 변경하지 않았다.

`KISA-2026-OPNsense-live.zip`에 TLS/HTTP/인증 API 응답·시각·판정·manifest를 비공개 보존했다. 브라우저 자동화는 현재 URL 확인을 보장하지 못해 종료됐으며, 브라우저 보안 경고를 우회하지 않았다. 이후 작업은 기존 CLI/읽기 전용 API로 수행했다.

## 최종 집계·남은 작업

| 상태 | 개수 |
|---|---|
| PASS | 13 |
| FAIL | 0 |
| NEEDS_REVIEW | 3 |
| NOT_TESTED | 0 |
| NOT_APPLICABLE | 0 |
| ERROR | 0 |

API 단위 오류 403이 없다는 뜻이 아니라, 해당 항목은 실제 부분 증거가 있어 **항목 수준 NEEDS_REVIEW**로 남겼다는 의미다. 3개를 PASS에 합산하지 않는다.

- S-06: 최소 읽기 권한의 실제 규칙 조회 또는 현재 콘솔 PF 원본, 인가·독립 비인가 출발지의 실제 접속 및 로그 상관 필요.
- S-07: 현재 제품 버전·관리 인터페이스/서비스 전체 설정, 평문 관리 채널 부재와 관찰 연결 경로 대조 필요.
- CA-09: 전체 규칙의 실제 필요성 검토·담당/주기와 과거 수행 이력 필요. 오늘 한 차례를 여러 회차로 만들지 않는다.

단일 실행 수집은 `scripts/run_kisa_remaining_local.ps1`, VM 콘솔의 읽기 전용 묶음은 `scripts/collect_opnsense_selected.sh`로 준비했다. 상세는 [후속 실행·증적 마감 절차](kisa-2026-external-followup.md).

Codex는 코드·자동 실행·원시 증적 대조와 보고서/PR을 수행했다. 사용자는 AWS 로그인 갱신, 기존 VM 시작과 키 파일 위치 제공을 했다. 사용자가 새 HTTP/SQL 진단 명령을 직접 수행했다고 기술하지 않는다.
