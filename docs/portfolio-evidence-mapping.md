# 진단 항목별 검증 근거

> 서버·네트워크·DBMS·WEB/WAS·보안장비 및 AWS 설정 진단의 항목별 근거를 기록했다. 2026-11-07 KST 기준 코드와 저장된 실습 자료를 대조했으며, 이 과정에서 실장비를 재조회하거나 설정을 변경하지 않았다.

## 읽는 기준과 기여 구분

- **구현:** 소스와 테스트가 존재한다. 합성 단위 테스트의 PASS를 실제 장비 PASS로 바꾸지 않는다.
- **저장된 실제 LAB:** 당시 수집 JSON·수동 파일·패킷 기록이 존재한다. 이번 검토는 그 파일의 재분석이며 현재 장비 상태가 아니다.
- **수동 확인:** PowerShell 출력·화면·실습 전사본 등 수동 시험 기록이다. 자동 수집값과 구분하고 시각·범위가 없으면 만들어 넣지 않는다.
- **독립 재확인 한계:** 요약 PASS만 있거나 원시 로그가 없으면 해당 동작의 전체 증거를 독립 재확인했다고 쓰지 않는다. 해시 일치는 파일 무결성이지 출처 인증이 아니다.
- 기준은 내부 LAB 식별자다. 확인하지 않은 KISA 공식 번호·인증·고객사 기준 준수는 주장하지 않는다.

팀 프로젝트의 스캐너·DB·CVE 후보·위험평가 흐름을 기반으로 개인이 공통 설정 진단,
대상별 수집·규칙, 격리 실습, 증적 인덱스, 재점검과 JSON/PDF 계층을 확장했다.
기존 팀 코드 전체를 개인 기여로 설명하지 않는다. 근거 소스는 [공통 엔진](../config_audit/engine.py),
[결과 모델](../config_audit/reporting.py), [증적](../config_audit/evidence_index.py),
[비교](../config_audit/comparison.py)와 각 영역 아래 링크다.

**Suricata IDS/IPS는 최종 검증 성과와 개선 집계에서 제외한다.** 과거 Day3 IDS 기록·기존 코드는 유지한다. 아래 분야 간 개선 수치를 더해 고유 취약점 총계로 만들지 않는다.

## ① 서버 — Linux / Windows Server

### Linux

- 대상/수준: 격리 Replay LAB의 Ubuntu 24.04. 읽기 전용 유효 설정·파일 메타데이터·리스너·로그 경로 수집 후 같은 LAB 재점검.
- 구현: [linux_mysql_lab.py](../config_audit/collectors/linux_mysql_lab.py), 기존 [linux_ssh.py](../config_audit/collectors/linux_ssh.py) 재사용. 실행·개선은 [복구 실습 문서](phase2-linux-mysql-recovery.md).

| ID | 기준·수집 방법 | 실제 Before→After | 위험 근거·대책 |
|---|---|---|---|
| LINUX-LAB-001 | `sshd -T` PermitRootLogin=no | yes→no, FAIL→PASS | 직접 root 관리 노출. root 직접 로그인 제한 |
| LINUX-LAB-002 | `sshd -T` PasswordAuthentication=no | yes→no, FAIL→PASS | LAB의 암호 인증 노출. 키 접근을 먼저 확보하고 암호 인증 제한 |
| LINUX-LAB-003 | root 소유 regular 파일, symlink 없음, 승인된 제한 권한 | shadow 0666→0640, sshd_config 0666→0600, FAIL→PASS | 중요 인증/설정 파일 쓰기 노출. 소유권·파일 형태·권한 함께 확인 |
| LINUX-LAB-004 | LAB demo TCP 9000 리스너 없음 | 존재→없음, FAIL→PASS | 불필요 서비스 노출. 해당 demo 프로세스 중지 |
| LINUX-LAB-005 | rsyslog 실행 + 명시된 auth/authpriv 경로 + 시작 구성 일치 | 경로 비활성→활성, FAIL→PASS | 인증 로그 경로 미설정. 경로 적용 후 구성 재조회 |

증적 E1/E2, 보고서 E3/E4. Linux 5건이며 MySQL 5건과 합쳐 Replay 10건이다.
실제 SSH 로그인, rsyslog 이벤트 전달/중앙 보관, 전체 서비스·PAM·모든 계정 감사,
재부팅 후 영속성까지 검증한 것은 아니다.


### Windows Server

- 대상: Windows Server 2022 Standard Evaluation, build 20348, Server Core 저장 자료. 2019/2025 실검증 완료로 표시하지 않는다.
- 구현: [수집 PowerShell](../scripts/collect_windows_server.ps1), [수집기](../config_audit/collectors/windows_server.py), [LAB 평가](../config_audit/windows_lab.py), [STRICT 정책](../config_audit/windows_policy.py), [기준 JSON](../rules/windows-server-personal-lab.json).
- 자동 수집 E5/E6과 수동 PowerShell 확인 E7을 **오프라인 재분석**하여 PASS 8 / NEEDS_REVIEW 1, LAB 조치·재점검 3건을 재현했다. 새 VM 수집이 아니다.

| ID | 내부 LAB 기준·방법 | 확인 결과·개선 및 출처 |
|---|---|---|
| WIN-LAB-001 | 로컬 Guest 비활성, 내장 계정 식별 | 자동값 enabled=false, PASS |
| WIN-LAB-002 | 최소 길이 14자 이상 | 수동 0→14, PASS·LAB 개선 완료 |
| WIN-LAB-003 | 복잡성 활성 | 수동 1→1, PASS 유지, 신규 개선 건수에 넣지 않음 |
| WIN-LAB-004 | 잠금 임계 10회, 기간/초기화 30분 | 수동 임계 0→10 및 30/30 확인, PASS·LAB 개선 완료 |
| WIN-LAB-005 | Spooler/인쇄 기능 부재 + 인쇄 불필요 | 자동 1060·기능 미설치, 수동 required=false 결합, 제한 범위 PASS |
| WIN-LAB-006 | 점검 대상 방화벽 프로필·서비스 활성 | 자동 Domain/Private/Public 활성, PASS |
| WIN-LAB-007 | SMBv1 비활성 | 자동 false, PASS |
| WIN-LAB-008 | SMB 서버 서명 필수 | 수동 별도 시나리오 False→True + 현재 자동 True, PASS·LAB 개선 완료 |
| WIN-LAB-009 | GUID 기반 Logon/Credential Validation/User Account Management/Audit Policy Change/Process Creation 기준 | 의미 분석 구현, 실제 필요한 구조화 값 부족, NEEDS_REVIEW |

암호 길이·잠금 기준은 추측/계정 공격 방어 목적의 내부 기준이고, SMB 서명은 통신 무결성 요구다.
조치는 해당 내부 기준 적용 후 재조회이며 도메인 전체 GPO 적합성이나 모든 SMB 클라이언트 호환성을 뜻하지 않는다.
**E5/E6의 security_policy에는 merged_policy=true만 있고 암호·잠금 수치가 없다.**
따라서 0→14·0→10을 그 자동 JSON에서 읽었다고 표현하면 안 된다.
SMB의 최신 baseline 자동값도 이미 True여서 과거 False는 E7의 별도 수동 시나리오다.
수동 기록의 verified_at=null을 실제 시험 시각으로 채우지 않는다.
초기 windows-before.json은 시계 오류 이력이 있어 정상 baseline으로 재사용하지 않는다.
STRICT 비교와 LAB 결과는 다르며 [Windows 문서](phase2-windows-server.md)의 고급 미검증 결과를 보존한다.
현재 프로젝트 reports/에서 별도 Windows 최종 LAB JSON/PDF 파일은 확인하지 못했다.
생성기 구현과 저장 원본 재분석 가능성을 설명하고 “완성된 Windows PDF 원본 확인”으로 확대하지 않는다.


## ② 네트워크 — Router / Switch

- 대상: FRRouting 기반 Linux 컨테이너와 Docker Linux bridge. Cisco/실물 Router/Switch가 아니다.
- 구현: [network_devices.py](../config_audit/collectors/network_devices.py), [network_packets.py](../config_audit/network_packets.py), [LAB 문서](phase2-network-devices.md), [패킷 문서](phase2-network-packets.md).

| ID | 방법·판정 기준 | 실제 확인 및 대책 |
|---|---|---|
| NET-LAB-R01 | SSH root/암호 인증·관리 listen 제한 | SSH 미설치, NOT_APPLICABLE. SSH 보안을 실검증했다고 하지 않음 |
| NET-LAB-R02 | 외부 Telnet/FRR TCP VTY 리스너 없음 | PASS. 관리 채널은 로컬 Docker exec/vtysh 범위 |
| NET-LAB-R03 | 소유 nft input default drop, loopback/established-related/ICMP 예외만 허용 | accept→drop, FAIL→PASS. nft JSON의 전용 chain만 확인, Docker NAT와 혼동하지 않음 |
| NET-LAB-R04 | LAB의 불필요한 HTTP/demo 리스너 없음 | 0.0.0.0:8080 demo 중지 후 FAIL→PASS |
| NET-LAB-R05 | FRR 실행 구성의 stdout 로그 활성 | NOT_TESTED. 로그 전달 성공을 주장하지 않음 |
| NET-LAB-S01 | Switch 관리면 접근 제한 | Docker bridge 관리 CLI 없음, NOT_APPLICABLE |
| NET-LAB-S02 | 802.1Q VLAN filtering/포트 멤버십 | 미구현, NOT_APPLICABLE. Docker bridge 분리=VLAN 검증 아님 |
| NET-LAB-S03 | 기대한 LAB endpoint만 data bridge에 연결 | PASS, 가상 endpoint 목록만 검사. 물리 unused port shutdown 아님 |

관리 접근 노출을 줄이도록 전용 input 정책과 demo 서비스를 개선했다.
E8/E9에서 R03/R04 개선 2건이 확인된다. 기존 packet-existing.json은 양방향 실패를
보존했고 별도 fabric LAB의 E10은 양방향 각 3/3, 손실 0%, 모든 경유 단계 및 TTL hop 확인이다.
서로 다른 토폴로지의 패킷 결과를 같은 자산의 단순 FAIL→PASS 비교로 합치지 않는다.
이 ICMP 성공은 R03 관리 접근 차단 시험이 아니며 설정 결과와 별도 증거다.
전용 Network PDF 원본은 확인하지 못했으며 JSON/공통 결과 어댑터 구현으로 설명한다.


## ③ DBMS — MySQL

- 대상: 별도 Replay LAB의 MySQL 8.4.13. 고정 읽기 전용 SELECT로 계정 목록/설정/권한을 정규화한다. 비밀번호 값은 수집하지 않는다.
- 구현: [linux_mysql_lab.py](../config_audit/collectors/linux_mysql_lab.py), 기존 [mysql_config.py](../config_audit/collectors/mysql_config.py), [실습 구성](../lab/phase2-linux-mysql/compose.replay.json).

| ID | 기준·방법 | 실제 Before→After | 위험·조치 |
|---|---|---|---|
| MYSQL-LAB-001 | mysql.user 익명 계정 수=0 | 1→0, FAIL→PASS | 식별되지 않은 계정 접근. LAB 익명 계정 삭제 |
| MYSQL-LAB-002 | root의 비-loopback Host 없음 | 1→0, FAIL→PASS | 최고권한 원격 노출. 원격 root 제거·로컬 관리 유지 |
| MYSQL-LAB-003 | GLOBAL local_infile=0 | 1→0, FAIL→PASS | 불필요한 로컬 파일 import 경로. 기능 비활성화 |
| MYSQL-LAB-004 | GLOBAL require_secure_transport=1 | 0→1, FAIL→PASS | 비보호 TCP 허용 위험. 안전한 전송 요구 설정 |
| MYSQL-LAB-005 | 지정 앱 계정은 지정 테이블 SELECT, roles/proxy/mandatory roles 없음 | EXCESSIVE→USAGE/SELECT_LAB_TABLE, FAIL→PASS | 과도한 권한의 영향 범위. 전역 권한 회수·테이블 SELECT만 부여 |

E1/E2/E3/E4에서 DBMS 5건과 Linux 5건의 개선을 확인했다. Unix socket으로 설정을
읽었으므로 MYSQL-LAB-004 PASS는 TCP TLS handshake·인증서 신뢰·cipher 검증이 아니다.
지정 앱 계정 외 전체 사용자 유효 권한을 감사했다고 하지 않는다. GLOBAL 값의 확인이며
재부팅 영속성·운영 데이터 보호까지 포함하지 않는다.

**Day2 구분:** `logs/day2-before.json` / `logs/day2-after.json`의
LAB-SSH-002와 LAB-MYSQL-002는 원본 FAIL→PASS 2건, 나머지는 PASS 유지다.
Day5 엄격 비교는 메타데이터 부족으로 UNVERIFIABLE 4건이다.
이 2건을 Phase2 Replay 10건과 같은 baseline/집계로 취급하지 않는다.


## ④ WEB/WAS — Nginx / Tomcat

- 대상: 저장된 실행 버전 Nginx 1.30.6 / Tomcat 10.1.61 격리 컨테이너. 버전 지원 전체를 보장하지 않는다.
- 구현: [web_was.py](../config_audit/collectors/web_was.py), [LAB](../lab/phase2-web-was/compose.json), [실습 매뉴얼](phase2-web-was.md).
- nginx 유효 구성·Tomcat 명시 설정과 현재 실행의 health/error/path/log 표식을 구분한다. 기본값을 임의로 적용값으로 채우지 않는다.

| ID | 위험·내부 기준 | 실제 개선/재점검 |
|---|---|---|
| WEB-LAB-N01 | 디렉터리 파일 목록 노출 제한 | autoindex on→off, /files/의 목록 접근 제한 확인 |
| WEB-LAB-N02 | 제품 버전 노출 최소화 | server_tokens on→off + 응답/오류의 버전 숨김 확인 |
| WEB-LAB-N03 | 불필요한 데이터 경로 공개 제한 | /private/ 정적 경로→404 확인 |
| WEB-LAB-N04 | 요청 추적을 위한 접근 로그 | access_log off→활성, 검증 요청 표식 기록 확인 |
| WAS-LAB-T01 | 예상치 못한 자동 배포 제한 | Host autoDeploy true→false 재조회 |
| WAS-LAB-T02 | 불필요 기본 앱 제거 | LAB before의 docs/examples 존재→없음. manager/host-manager 부재도 확인 |
| WAS-LAB-T03 | 오류 상세/서버 정보 노출 제한 | showReport/showServerInfo false, 중립 Server 값 + 오류 응답 확인 |
| WAS-LAB-T04 | WAS 요청 추적 | AccessLogValve 추가, 현재 요청 표식 확인 |

E11/E12는 8개 모두 FAIL→PASS, 비교 개선 관찰 8건이다. E13/E14 PDF도 존재한다.
전후 `http_verification.status=PASS`, 범위는 nginx_to_tomcat_lab_health_endpoint다.
Tomcat before에서 manager 취약 인증을 재현한 것은 아니며 실제 추가한 기본 앱은 docs/examples다.
버전 숨김만으로 특정 CVE가 해소됐다고 하지 않는다. autoDeploy는 이 LAB 기준이며 모든
운영 배포 방식에서 일률적으로 취약하다는 의미가 아니다. TLS·전체 웹 취약점·부하 검증은 제외다.


## ⑤ 보안장비 — OPNsense / ModSecurity

### OPNsense

- 대상: Hyper-V의 OPNsense LAB. 수집 API, PF 스냅샷, 수동 패킷 시험을 별도 검증 채널로 관리한다.
- 구현: [opnsense.py](../config_audit/collectors/opnsense.py), [PF](../config_audit/collectors/opnsense_pf.py), [로그·규칙](../config_audit/collectors/opnsense_log_rules.py), [수동 증거](../config_audit/manual_evidence.py).

| ID | 기준·방법 | 확인 결과·대책/미해결 조건 |
|---|---|---|
| FW-01 | LAN/WAN 할당·주소·활성, 필수값 누락 시 PASS 금지 | 과거 사용자 API PASS 기록. 완전한 Day4 자동 실행 JSON은 없어 새 자동 결과를 만들지 않음 |
| FW-02 | WAN에서 방화벽 자체 HTTPS 관리 접근 제한 | 수동 TCP 443 timeout + block 로그, 한정 PASS. LAN 관리 접근과 구분 |
| FW-03 | WAN 비인가 접근과 승인 예외 구분 | 수동 TCP 22 timeout + 기본 차단 로그, 한정 PASS. WAN→LAN 전달은 미시험 |
| FW-04 | 활성/Quick/순서/적용 범위·과도 허용 | Rules Inspect·PF 일부 분석. API 403, 전체 앵커/동적 정책 미확인, NEEDS_REVIEW |
| FW-05 | 현재 시험과 action/tuple/시각/rid/규칙 연계 | limit=20 로그 조회 성공과 list_rule_ids 403을 분리. 시각대·규칙 세대 연속성 부족, NEEDS_REVIEW |
| FW-06 | 정책에 따른 ICMP 허용·차단·복구 대조 | 4/4→0/4 및 ICMP block→복구 4/4, 해당 실습 수동 PASS |

E15의 수동 로더 재검증에서 FW-02/03/06은 PASS/VALID/attached=true,
FW-04/05는 NEEDS_REVIEW/VALID/attached=true다. VALID는 첨부 조건·해시 충족이며 전체 정책 PASS가 아니다.
IP/포트별 관리 접근 노출을 제한하되 자동 정책 변경은 하지 않도록 설계했다.
차단 실습 규칙은 종료 후 비활성화 기록을 유지한다. 숫자 rulenr만으로 PF 규칙을 확정하지 않으며,
기존 로그를 현재 실행 증거로 취급하지 않는다. 필요한 후속 자료는 시험 시각대·출발 포트·
전후 규칙 세대·동일 캡처 맥락이다. [FW-05 상세](opnsense-log-rule-evidence.md).


### ModSecurity

- 구현/기준: [modsecurity.py](../config_audit/collectors/modsecurity.py), [Day3 실행기](../scripts/run_day3_audit.py), [역사적 기록](../lab/day3/README.md#과거-day3-실습-개발검증-기록).
- WAF-01 SecRuleEngine On, WAF-02 SecAuditEngine RelevantOnly, WAF-03 JSON 감사 로그,
  WAF-04 요청 본문 검사 On, WAF-05 CRS 로드/차단 수준 1·inbound 임계 5,
  WAF-06 GET 200·PUT 403·동일 요청 ID/URI의 규칙 911100/949110 감사 이벤트를 확인하는 코드가 있다.
- 엔진 미적용·본문 미검사·로깅 부재를 위험으로 판단하고 명시 설정/Include 순서/CRS 로드 및
  요청/감사 이벤트를 재확인하도록 구현했다. 광범위 예외 규칙을 추가해 PASS를 만들지 않는다.
- E16에 WAF 6개 PASS 요약과 컨테이너 감사 참조가 있다. 당시 실습 수행 기록은 있으나
  별도 원시 GET/PUT 응답·ModSecurity 감사 JSON 원본 파일은 현재 자료에서 확인하지 못했다.
  따라서 이 자료만으로 **실제 차단 성공을 독립 재확인할 수 없다**. WAF 6건을 개선 6건으로 집계하지 않는다.
- 재검증에는 같은 실행 ID의 정상 요청·차단 요청·원시 감사 이벤트를 함께 보존해야 한다.
  운영환경 WAF 우회 방어 또는 모든 공격 차단으로 확대하지 않는다.


## 추가 영역 — AWS 클라우드

- 구현: [aws_live.py](../cloud_security/aws_live.py), [범위](../cloud_security/aws_scope.py), [관찰 정규화](../cloud_security/aws_observations.py), [판정](../config_audit/collectors/aws_security.py), [JSON/PDF](../config_audit/aws_report.py).
- 표준 credential chain/IAM 역할, STS 계정 gate, 계정·리전·리소스 allowlist,
  읽기 API 목록·페이지/호출/시간 제한을 적용한다. 문서상 근거 대조 시 실제 AWS API를 호출하지 않았다.
- E17/E18/E19에서 실제 독립 LAB 네 항목 FAIL→PASS 및 개선 관찰 4건을 확인했다.

| ID | 기준·수집·위험 근거 | 저장 자료의 결과·조치 |
|---|---|---|
| IAM-01 | 계정 요약의 root 액세스 키 존재 여부 | 키 없음, PASS 유지. LAB를 위해 root 키 생성 금지 |
| IAM-02 | root MFA 및 중앙 관리 적용 문맥 | MFA 활성, PASS 유지. 실제 유효 관리 권한 전체 증명 아님 |
| IAM-03 | 지정 역할의 Action/Resource/Condition과 내부 기준 | 허용 기준 미확정, NEEDS_REVIEW 유지. Resource=*만으로 FAIL/PASS를 단정하지 않음 |
| SG-01 | 민감 포트의 명시적 전체 공개 CIDR | 미부착 SG의 TCP 21/23/3389 공개 규칙 제거, FAIL→PASS. 실제 도달성 아님 |
| NACL-01 | 번호 우선순위·요청/반환 방향의 유한 관리 시험 행렬 | allow 100 앞에 deny 50/51/52 추가, FAIL→PASS. 모든 IP/포트나 실제 패킷 차단 아님 |
| VPC-01 | 명시한 내부 Subnet의 공인 IP·IGW 경로·연결 | 자동 공인 IPv4 끔, 직접 IGW 기본 경로 제거, FAIL→PASS. 기존 Default VPC를 내부망으로 임의 지정하지 않음 |
| CT-01 | 서울 리전 지속 관리 이벤트 Trail의 전체 조회/상태 | 필요한 Trail 부재, FAIL 유지. Event History 부재를 뜻하지 않음 |
| FL-01 | 동일 VPC 범위 ALL Flow Logs 구성·활성 | 미설정→활성 구성, FAIL→PASS. 실제 로그 발생·전달 성공은 NOT_TESTED |

NACL 기준은 문서용 시험 주소의 지정 TCP 22/23/3389 및 반환 포트 55000 행렬에 한정한다.
기존 Default VPC·EC2·SSM 역할을 개선한 실습이 아니라 별도 Terraform LAB이다.
비교 manifest 참조 18개 파일의 SHA-256/크기를 다시 대조해 모두 일치했다.
계정 ID/실제 리소스 ID·state·개인 tfvars는 이 공개 문서에 싣지 않는다.
AWS LAB 삭제는 미완료이며 현재 자원·비용·삭제 Plan은 별도 인증과 조회가 필요하다.


## 증적 및 보고서 목록

아래는 **저장소 루트 기준 비공개 로컬 경로**다. 일반 공개 체크아웃에 파일이 없을 수 있으므로 Markdown 다운로드 링크나 공개 증거로 취급하지 않는다. 파일명과 요약을 설명할 뿐 원본을 Git에 추가하지 않는다.

| 참조 | 실제 경로 / 확인한 자료 |
|---|---|
| E1/E2 | `logs/phase2-linux-mysql-replay/before-v1.json`, `logs/phase2-linux-mysql-replay/after-v1.json` |
| E3/E4 | `reports/phase2-linux-mysql-replay/before-v1.pdf`, `reports/phase2-linux-mysql-replay/after-v1.pdf` — PDF 헤더/존재 확인 |
| E5/E6 | `logs/phase2-windows/windows-followup-v02.json`, `logs/phase2-windows/windows-password-after-v02.json` |
| E7 | `evidence/phase2-windows/manual-lab.json` — user_powershell_confirmation, 일부 시각 없음 |
| E8/E9 | `logs/phase2-network/before.json`, `logs/phase2-network/after-v3-live.json` |
| E10 | `logs/phase2-network/packet-fabric.json`; 실패 보존은 `logs/phase2-network/packet-existing.json` |
| E11/E12 | `logs/phase2-web-was/before.json`, `logs/phase2-web-was/after.json` |
| E13/E14 | `reports/phase2-web-was/before.pdf`, `reports/phase2-web-was/after.pdf` — PDF 헤더/존재 확인 |
| E15 | `evidence/day4/manual.json`, `evidence/day4/screenshots/`, `evidence/day4/fw06-restore-ping.txt` |
| E15 보조 | `evidence/day4/fw04-active-rules.txt`, `fw04-active-rules-detail.txt`, `fw04-rules.tar`, `fw05-wan-tcp22.json`, `fw05-wan-tcp22-retest.json` (모두 `evidence/day4/` 아래) |
| E16 | `logs/day3-final.json` — WAF PASS 요약. 감사 참조는 컨테이너 내부 참조이며 원시 감사 파일 미확인 |
| E17 | `reports/phase2-aws-audit-lab/execution-1710f9035cd4401b834a6ac1cf4c76c9/before/20261106T152803Z-f4cb859484b741c78e57f66f60c3fd86/`의 snapshot/report/collection/manifest JSON 및 report.pdf |
| E18 | `reports/phase2-aws-audit-lab/resume-24e274c8ad574cb1b91edda684415f92/after/20261106T154952Z-30e9f0f868f34925bc76a4f9ac348063/`의 같은 파일 구성 |
| E19 | `reports/phase2-aws-audit-lab/resume-24e274c8ad574cb1b91edda684415f92/comparison/`의 comparison.json/pdf와 manifest.json |

AWS 원본 명칭은 before.json/after.json이 아니라 각 실행의 snapshot.json/report.json이다.
Windows 최종 LAB 보고서, Network 전용 PDF, WAF 원시 감사 파일은 위 범위에서 미확인이다.
없어진 파일을 추정해 추가하거나 새로 만든 결과를 당시 원본으로 표시하지 않는다.

Day5의 `reports/day5/day5-integrated-report.json/pdf` 등은 과거 산출물이다.
5자산·21고유항목·25레코드에는 역사적 IDS 채널도 들어 있으므로 현재 IDS 제외 성과의
합계로 사용하지 않는다. Phase2를 넣어 원본을 재작성하지 않았다.
공개 데모는 [합성 샘플 설명](../examples/day5-demo/README.md)과 [JSON](../examples/day5-demo/sample-integrated-report.json),
[PDF](../examples/day5-demo/sample-integrated-report.pdf)이며 실제 LAB 결과의 원본이 아니다.

## 테스트 기록과 기준

| 기록 | 환경·범위 | 결과·해석 |
|---|---|---|
| 초기 330개 CI 링크 | [2026년 과거 CI](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39456387487) | 당시 실행 기록. 이번 작업에서 최신 CI로 재확인하지 않음 |
| Day3 381개 | 당시 사용자 Windows 콘솔 확인 기록 | [Day3 실습 및 과거 검증 기록](../lab/day3/README.md#과거-day3-실습-개발검증-기록). 당시 제한된 실행 환경 결과와도 구분 |
| Day5 694개 | 당시 Windows 단계별 회귀 기록 | 693 통과/환경 오류 1의 역사적 값, 현재 최신 수치 아님 |
| Git 통합 2026-11-07 | Windows / Python 3.12.10 / source 99c8f10 | 핵심 322 통과; 전체 1,301 중 1,300 통과·1 실패 |

Git 통합의 원본 `core-unittest.txt` / `full-unittest.txt`는 저장소 밖 비공개 작업기록에
보존돼 있다. 전체 실패는 `test_ec2_owner_deployment_script_syntax`의
WSL `execvpe(/bin/bash) failed: No such file or directory`였다. 다른 시점의
WinError 1920/0xC0000022를 같은 오류 메시지로 복사하지 않는다.

### 2026-11-07 회귀 테스트

- 실행 완료: **2026-11-07 13:41:56 KST**, Windows / Python 3.12.10.
- 대상: source `99c8f10` 기준. 문서 정리 중 진단 코드·테스트 파일은 변경하지 않았다.
- 핵심 공통 엔진·Day4·Day5 선택 테스트: **322개 통과, 실패 0**.
- 전체 `unittest discover`: **1,301개 실행, 1,300개 통과 / 1개 실패** (18.427초).
- 실패는 위와 같은 기존 WSL `/bin/bash` 부재이며 새 기능 회귀로 분류하지 않았다.
- 원본 로그 `core-unittest.txt`, `full-unittest.txt`는 저장소 밖 비공개 문서 검증 작업기록에 보존했다.
  테스트 실패를 skip/삭제하거나 성공으로 표시하지 않았다. GitHub CI 결과는 별도다.


Windows 실행 명령:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
```

테스트가 통과해도 실제 LAB 실행을 대신하지 않는다. 원본이 없는 공개 체크아웃은
실제 증적 의존 테스트의 기존 적용 조건 때문에 숫자가 달라질 수 있다.
CI 배지는 동적 상태이며 이 로컬 기록이 새 GitHub Actions 성공을 보장하지 않는다.


## 초기 팀 프로젝트·격리 실습 검증 기록 (2026-10-20, 과거 자료)

다음 기록은 2026-10-20 무렵의 초기 팀 프로젝트 및 격리 실습 관찰이다. 현재 KISA 16개 항목 판정 및 2026-11-09 CI와 별개이며, 운영 환경의 진단·인증 완료를 뜻하지 않는다. 기존 분리된 검증 문서의 고유 결과와 증적 링크를 통합했다.

### 1. 과거 자동 테스트와 CI

- 과거 Python 전체 회귀 테스트 **330개 통과** ([기본 CI 실행 기록](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39456387487))
- 승인 Scope, 서비스 fingerprint, CVE 영향 버전 매핑, 증적 중복 방지, 위험도 평가, 스냅샷 보고서, 비밀정보 검사 등 테스트
- [격리 Docker 통합 CI](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39453811884): MySQL V6→V7 마이그레이션, 기존 데이터 보존, FTP·SSH·HTTP·DVWA·Nuclei 실습, 증적 해시 및 JSON/PDF 생성 확인

실행:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s .\tests -p "test_*.py" -v
.\.venv\Scripts\python.exe -m compileall -q .\asset_management .\scanner .\db .\scripts .\analysis .\verification .\api
.\.venv\Scripts\python.exe -B .\scripts\check_secrets.py
docker compose -f .\docker\docker-compose.yml config --quiet
```

### 2. EC2 및 로컬 실습

2026-10-20 기준 승인된 실습 자산에서 수집한 관찰 결과입니다.

| 검사 항목 | 관찰 결과 | 해석 |
|---|---|---|
| FTP 익명 인증 | `230 Login successful` | 해당 서비스의 익명 인증 허용 설정 확인 |
| SSH 기본 인증 정책 | 비밀번호 인증 비활성 | 확인 범위 내 기본 설정이며 전체 SSH 정책 검증은 아님 |
| HTTP 보안 헤더 | 4종 헤더 누락 | 해당 응답의 보안 헤더 미설정 |
| DVWA SQLi 실습 | 정상 1행 / 우회 5행 | 승인된 실습 응답에서 조건 우회 확인 |
| 로컬 정상 HTTP | 점검 항목 미발견 | 특정 검사에 한정된 NOT_DETECTED |

저장 결과 화면에서 EC2 4건과 로컬 HTTP 1건의 증적 **5/5 MATCH**, 보고서 Snapshot MATCH 및 VERIFIED를 확인했습니다. 여기서 MATCH는 저장된 증적의 내용 무결성 비교이며, 원격 출처 인증·전체 취약점 커버리지를 뜻하지 않습니다. 원본 보고서 파일을 별도로 독립 재해싱한 결과와도 구분합니다.

### 3. 같은 대상의 개선 전후 검증 — Docker

GitHub Actions 일회용 Docker 환경에서 동일한 서비스 대상으로 조치 전후를 검증했습니다.

| 검사 | 조치 전 | 개선 후 동일 대상 재점검 |
|---|---|---|
| FTP 익명 인증 | CONFIRMED | NOT_DETECTED |
| HTTP 보안 헤더 | POTENTIAL | NOT_DETECTED |
| Nuclei HTTP 템플릿 | POTENTIAL | NOT_DETECTED |

**실제 AWS EC2 설정을 변경한 결과가 아닙니다.** 별도 SQLite SQL 앱과 DVWA의 결과도 같은 서비스의 개선 전후로 취급하지 않습니다.

### 4. 판정 상태

| 상태 | 의미 |
|---|---|
| CANDIDATE | 서비스·버전과 공개된 영향 범위가 일치하는 후보 |
| POTENTIAL | 특정 설정 또는 템플릿 기준 위험 가능성 |
| CONFIRMED | 해당 검사·실습에서 직접 확인한 동작/설정 (CVE 확정과 구분) |
| NOT_DETECTED | 실제 수행한 검사 범위에서 미발견 |
| ERROR / INCONCLUSIVE | 검사 실패 또는 결론 도출 불가 |
| NOT_TESTED | 유효 증적 없음 또는 해당 범위 미검사 |

CVE 후보 4개는 검토한 공식 영향 범위에 한정합니다. 미일치는 안전 판정이 아닙니다. CVSS·EPSS·KEV는 검토 우선순위 자료이며, 취약 확정 기준이 아닙니다.

### 5. 대표 증적

- [서비스 식별·Scope](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/0806691a1baf8df509376b3de8e69d3a017e51a2/docs/images/01-scope-service.png)
- [CVE 후보 판단](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/0806691a1baf8df509376b3de8e69d3a017e51a2/docs/images/02-cve-candidate.png)
- [설정·실습 증적 검증](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/0806691a1baf8df509376b3de8e69d3a017e51a2/docs/images/05-v7-integrity.png)
- [Docker 동일 대상 재점검](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/0806691a1baf8df509376b3de8e69d3a017e51a2/docs/images/06-docker-retest.png)
- [통합 보고서 무결성](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/0806691a1baf8df509376b3de8e69d3a017e51a2/docs/images/07-integrated-report.png)

#### 검증 한계

AWS Security Group 설정만으로 실제 인터넷 도달성을 확정할 수 없습니다. SSH 정책은 조건부 Match나 실행 인수까지 전부 포함하지 않습니다. Nuclei 템플릿 매칭을 특정 CVE의 자동 확정으로 해석하지 않습니다. 실습환경 검사와 실제 운영환경 보안 적합성·ISMS-P 인증은 구분합니다.
