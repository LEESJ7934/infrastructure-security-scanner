# 면접용 KISA 대표 사례 설명

현재 선정 16개 중 격리 실측 PASS는 6개(37.5%), 미측정 10개다. 아래 설명은 본인이 이해하고 직접 재현할 수 있도록 준비한 자료이며 고객사 수행·인증이나 사용자의 직접 실습 이력을 새로 만들어 주지 않는다. 공식 기준은 일반 권고이며 개인 LAB 해석을 구분한다.

## 기여를 설명하는 문장

팀의 포트·서비스·CVE·DB·보고서 기반 위에 개인 LAB 설정진단을 확장했다. 이번 변경은 Codex가 기존 엔진을 재사용하여 코드와 문서를 작성하고 GitHub Actions에서 자동 실습했다. 나는 코드를 검토하고 아래 명령과 기준, 운영 영향을 설명하며 직접 재현한 범위만 나의 수동 수행으로 말한다. 기존 수동 Windows/OPNsense 실습은 원래 출처와 한계를 유지한다.

“내부 LAB의 PASS와 KISA 권고의 PASS가 다름을 발견했습니다. shadow 0640은 내부 기준을 만족해도 KISA U-18에는 맞지 않아 별도 0400 실습과 재수집을 준비했습니다. 이번 자동 격리 실습에서는 Linux 2개·Windows 4개가 PASS이고, 전체 계정·장비·클라우드 기준을 검증하지 못한 10개는 미완료로 표시했습니다.”

## U-01 root 계정 원격 접속 제한

1. 점검 이유: root 원격접속 탈취 시 시스템 전체 제어 가능.
2. KISA/개인 LAB 판단: PDF 12쪽. All effective root SSH contexts denied; Telnet and other remote terminals absent or deny root.
3. 방법·명령: `sshd -T -C user=root,host=lab,addr=<관리IP>; /proc/net/tcp*; SSH 설정 Include/Match와 원격터미널 목록`
4. 취약 설정 위협: root 원격접속 탈취 시 시스템 전체 제어 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: PermitRootLogin no; verify Match contexts, alternate management and remote terminal inventory. 키 기반 별도 관리자와 콘솔을 먼저 확보. Match 구간까지 no인지 확인하며 운영 SSH 중단 위험 관리.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 실측은 최종 대장의 run/artifact 링크에서 확인한다.

## U-18 /etc/shadow 파일 소유자 및 권한 설정

1. 점검 이유: 비밀번호 해시 노출 후 오프라인 크래킹 가능.
2. KISA/개인 LAB 판단: PDF 44쪽. root-owned regular non-symlink; mode permits only root read.
3. 방법·명령: `stat -c "%u %a %F" /etc/shadow; test -L /etc/shadow`
4. 취약 설정 위협: 비밀번호 해시 노출 후 오프라인 크래킹 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: chown root /etc/shadow; chmod 400 /etc/shadow. 배포판 인증·백업 계정의 읽기 의존성 확인. 파일 내용이나 해시는 증적에 수집하지 않음.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 실측은 최종 대장의 run/artifact 링크에서 확인한다.

## W-02 Guest 계정 비활성화

1. 점검 이유: 임시 계정으로 비인가 접근 가능.
2. KISA/개인 LAB 판단: PDF 178쪽. Built-in SID RID 501 account disabled.
3. 방법·명령: `Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' } | Select-Object Enabled,SID`
4. 취약 설정 위협: 임시 계정으로 비인가 접근 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Disable built-in Guest identified by SID, regardless of localized name. 지역화/이름 변경과 관계없이 RID 501을 식별. Guest 사용 서비스 의존성 확인.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 실측은 최종 대장의 run/artifact 링크에서 확인한다.

## W-04 계정 잠금 임계값 설정

1. 점검 이유: 자동화된 암호 대입을 제한.
2. KISA/개인 LAB 판단: PDF 180쪽. Enabled threshold 1-5 attempts (zero means disabled).
3. 방법·명령: `secedit /export /cfg <새파일.inf> /areas SECURITYPOLICY; net accounts`
4. 취약 설정 위협: 자동화된 암호 대입을 제한. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: net accounts /lockoutthreshold:5 계정 잠금으로 정상 사용자 업무 지연·고의 잠금 가능. 현재 값과 콘솔 복구 경로 확보.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 실측은 최종 대장의 run/artifact 링크에서 확인한다.

## W-08 계정 잠금 기간 설정

1. 점검 이유: 실패 횟수 초기화가 너무 빠르면 암호 대입 반복 가능.
2. KISA/개인 LAB 판단: PDF 185쪽. Enabled lockout, duration and counter reset each >=60 minutes.
3. 방법·명령: `secedit /export /cfg <새파일.inf> /areas SECURITYPOLICY`
4. 취약 설정 위협: 실패 횟수 초기화가 너무 빠르면 암호 대입 반복 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: net accounts /lockoutduration:60 /lockoutwindow:60 잠금과 초기화 두 값을 모두 확인. 임계값 0이면 잠금 기간만 있어도 효과 없음.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 실측은 최종 대장의 run/artifact 링크에서 확인한다.

## W-64 윈도우 방화벽 설정

1. 점검 이유: 호스트 인바운드/아웃바운드 접근통제 부재 위험.
2. KISA/개인 LAB 판단: PDF 270쪽. Domain/Private/Public effective ActiveStore profiles enabled.
3. 방법·명령: `Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled`
4. 취약 설정 위협: 호스트 인바운드/아웃바운드 접근통제 부재 위험. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Enable firewall after preserving permitted console/management access. 방화벽 활성화 전 관리·서비스 허용 규칙과 콘솔 확인. 로컬 정책과 적용 정책을 구분.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 실측은 최종 대장의 run/artifact 링크에서 확인한다.

## WEB-04 웹 서비스 디렉터리 리스팅 방지 설정

1. 점검 이유: 파일 목록·백업·소스 경로 노출.
2. KISA/개인 LAB 판단: PDF 280쪽. All scoped locations deny listing in effective config AND HTTP directory probes.
3. 방법·명령: `nginx -T; Tomcat conf/web.xml 및 앱 WEB-INF/web.xml; curl -i <LAB디렉터리URL>`
4. 취약 설정 위협: 파일 목록·백업·소스 경로 노출. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Nginx autoindex off; Tomcat listings false; reload and probe. 가상호스트·location·서블릿별 예외까지 확인. 재시작 전 설정 구문과 정상 서비스 점검.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 이번 선정 전체 조건은 NOT_TESTED이며 기존 내부 LAB PASS로 대체하지 않는다.

## WEB-07 웹 서비스 경로 내 불필요한 파일 제거

1. 점검 이유: 샘플·매뉴얼·백업에서 정보 노출 및 공격면 증가.
2. KISA/개인 LAB 판단: PDF 290쪽. Scoped deployment path inventory has no unnecessary files; HTTP probes confirm.
3. 방법·명령: `find <확정한배포루트> -type f; curl -i <LAB샘플URL>`
4. 취약 설정 위협: 샘플·매뉴얼·백업에서 정보 노출 및 공격면 증가. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Review path inventory and remove only LAB samples/manuals/backups; retest. 전체 경로 인벤토리와 파일 용도 검토 뒤 승인 LAB 파일만 제거. 403만으로 파일 제거를 입증하지 않음.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 이번 선정 전체 조건은 NOT_TESTED이며 기존 내부 LAB PASS로 대체하지 않는다.

## WEB-16 웹 서비스 헤더 정보 노출 제한

1. 점검 이유: 제품 버전·OS 노출로 공격자 취약점 탐색 지원.
2. KISA/개인 LAB 판단: PDF 316쪽. Effective information-hiding configuration AND normal/error HTTP responses minimized per product guide example.
3. 방법·명령: `nginx -T; Tomcat server.xml; curl -i <LAB정상URL>; curl -i <LAB없는URL>`
4. 취약 설정 위협: 제품 버전·OS 노출로 공격자 취약점 탐색 지원. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Nginx server_tokens off; Tomcat server generic and showServerInfo false. 정상·오류 및 직접 backend/프록시 경로 구분. Nginx 제품명 단독은 이번 제품 사례 기반 프로파일에서 허용.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 이번 선정 전체 조건은 NOT_TESTED이며 기존 내부 LAB PASS로 대체하지 않는다.

## D-02 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용

1. 점검 이유: 불필요 계정 유출 시 데이터 접근 가능.
2. KISA/개인 LAB 판단: PDF 600쪽. Complete account inventory reviewed against purposes; no unnecessary unlocked accounts.
3. 방법·명령: `SELECT User,Host,account_locked FROM mysql.user;`
4. 취약 설정 위협: 불필요 계정 유출 시 데이터 접근 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Review every account including system accounts; remove or lock unnecessary accounts. 시스템 계정과 앱 계정 목적을 모두 기록. 삭제 전 의존성·백업 검토; 익명 계정 0개만으로 PASS 불가.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 이번 선정 전체 조건은 NOT_TESTED이며 기존 내부 LAB PASS로 대체하지 않는다.

## D-04 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용

1. 점검 이유: 불필요한 관리자 권한으로 전체 DB 탈취·변경 가능.
2. KISA/개인 LAB 판단: PDF 608쪽. All global/dynamic privileges, roles, proxy and mandatory-role paths reviewed; administrators authorized.
3. 방법·명령: `SELECT GRANTEE,PRIVILEGE_TYPE,IS_GRANTABLE FROM INFORMATION_SCHEMA.USER_PRIVILEGES; SELECT USER,HOST,PRIV,WITH_GRANT_OPTION FROM mysql.global_grants; SELECT * FROM mysql.role_edges;`
4. 취약 설정 위협: 불필요한 관리자 권한으로 전체 DB 탈취·변경 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Inventory SUPER and modern dynamic privileges, recursively expand roles; revoke excess. SUPER 외 동적 권한·역할 상속·프록시도 포함. 앱 SELECT 한 계정만 검사해 전체 관리자 권한 PASS 불가.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 이번 선정 전체 조건은 NOT_TESTED이며 기존 내부 LAB PASS로 대체하지 않는다.

## D-10 원격에서 DB 서버로의 접속 제한

1. 점검 이유: 내외부 비인가 IP에서 DB 접근 가능.
2. KISA/개인 LAB 판단: PDF 628쪽. Complete Host and network policy inventory restricts DB to designated IPs; allowed/denied probes.
3. 방법·명령: `SELECT User,Host FROM mysql.user; Test-NetConnection <LAB_DB_IP> -Port 3306`
4. 취약 설정 위협: 내외부 비인가 IP에서 DB 접근 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Restrict all applicable account Hosts and ingress; test from designated and other source IPs. 접속 허용 IP·방화벽·Host 정책을 구분. 허용/비허용 서로 다른 출발지에서 실제 인증 또는 TCP 거부 시험.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 이번 선정 전체 조건은 NOT_TESTED이며 기존 내부 LAB PASS로 대체하지 않는다.

## S-06 보안 장비 원격 관리 접근 통제

1. 점검 이유: 관리 경로 노출로 방화벽 정책 탈취·무력화 가능.
2. KISA/개인 LAB 판단: PDF 363쪽. All scoped management interfaces allow designated source only, with positive/negative tests and policy mapping.
3. 방법·명령: `pfctl -sr; pfctl -vvsr; Test-NetConnection <관리IP> -Port 443`
4. 취약 설정 위협: 관리 경로 노출로 방화벽 정책 탈취·무력화 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Restrict management source IP after console/rollback preparation. 콘솔·rollback 확보 후 관리 전용 규칙 적용. 양쪽 출발지 시험과 실제 적용 PF/로그 매칭. API 200만으로 전체 정책 PASS 불가.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 이번 선정 전체 조건은 NOT_TESTED이며 기존 내부 LAB PASS로 대체하지 않는다.

## S-07 보안장비 보안 접속

1. 점검 이유: 평문 관리 세션의 계정정보 스니핑 가능.
2. KISA/개인 LAB 판단: PDF 364쪽. Scoped management channels use encryption; real TLS/SSH handshake and plaintext exclusion.
3. 방법·명령: `curl.exe --cacert <LAB_CA.pem> -I https://<관리호스트>/; ssh -vv <관리호스트>`
4. 취약 설정 위협: 평문 관리 세션의 계정정보 스니핑 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Use HTTPS/SSH; verify management path, certificate and unencrypted channel exposure. HTTP/Telnet 노출과 TLS/SSH 실협상을 분리 확인. 인증서/호스트키 신뢰를 기록; -k 성공만으로 신원 검증 주장 불가.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 이번 선정 전체 조건은 NOT_TESTED이며 기존 내부 LAB PASS로 대체하지 않는다.

## CA-07 VPC 네트워크 서브넷 관리

1. 점검 이유: 내부 자원이 공개 경로·공인 주소로 노출 가능.
2. KISA/개인 LAB 판단: PDF 860쪽. Public/internal resource separation validated with subnet route associations and public addressing.
3. 방법·명령: `aws ec2 describe-subnets; aws ec2 describe-route-tables; aws ec2 describe-instances`
4. 취약 설정 위협: 내부 자원이 공개 경로·공인 주소로 노출 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Separate scoped public/internal resources; inspect effective routes including main and IPv6. 독립 LAB 계정·리전·자원 범위 확인. main route association/IPv6 포함. subnet 플래그 한 개로 전체 분리 PASS 불가.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 이번 선정 전체 조건은 NOT_TESTED이며 기존 내부 LAB PASS로 대체하지 않는다.

## CA-09 접근 제어 설정 관리

1. 점검 이유: 불필요한 접근 규칙으로 비인가 접속 가능.
2. KISA/개인 LAB 판단: PDF 862쪽. SG/NACL source/destination/protocol/order reviewed; unnecessary rules absent AND periodic review records exist.
3. 방법·명령: `aws ec2 describe-security-groups; aws ec2 describe-network-acls`
4. 취약 설정 위협: 불필요한 접근 규칙으로 비인가 접속 가능. 해당 설정만으로 침해 사실이나 CVE 악용을 확정하지 않는다.
5. 개선·운영 영향: Review effective SG/NACL and retain genuine dated periodic review records; remove excess only in owned LAB. SG/NACL source/destination/protocol/order와 IPv6 검토. 실제 날짜의 반복 검토 기록이 필요하며 오늘 한 번 검사로 주기 실적을 만들지 않음.
6. 재점검·증적: 동일 자산·버전에서 같은 명령으로 재수집하고 설정+동작+원본 시각·파일 해시·출처를 연결한다. 이번 선정 전체 조건은 NOT_TESTED이며 기존 내부 LAB PASS로 대체하지 않는다.
