# Linux 및 MySQL 보안 설정 진단

**실행 오류 보완 및 실제 검증 완료:** 최초 rsyslog의 활성 action 누락으로 Linux가 종료되는 문제를 수정했다. 기존 개선 상태를 보존한 뒤 별도 replay LAB에서 실제 FAIL 10개 → PASS 10개를 확인했다. 현재 상태 보존·별도 재현 명령과 실제 증적은 [오류 복구 및 실제 검증 기록](linux-mysql-retest.md)을 우선 참고한다. 아래 최초 구현 단계의 미검증 기술은 당시 기록이며, 후속 실제 검증 결과와 구분한다.

이번 단계는 코드·구성·오프라인 테스트·보고서 준비이다. 실제 Docker 이미지 다운로드/빌드/실행과 설정 개선은 아래 사용자 PowerShell 명령으로 수행한다. 이번 Codex 작업에서 컨테이너나 호스트 정책을 변경하지 않았다. 합성 테스트 결과를 실제 조치 완료로 표시하지 않는다.

## 기존 코드 재사용 및 작업 보존

- `config_audit/collectors/linux_ssh.py`: 기존 OpenSSH 유효 설정 파서를 재사용한다.
- `config_audit/collectors/mysql_config.py`: 기존 MySQL 버전/시스템 변수 파서를 재사용한다.
- `config_audit/engine.py`, `models.py`, `statuses.py`: AuditAsset/AuditRule/Observation/evaluate()와 6개 기존 상태를 그대로 사용한다.
- `config_audit/reporting.py`: ReportResult/SourceSnapshot 어댑터로 연결한다. Phase2 별도 출처/day=0이며 기존 Day5 보고서에 결과를 삽입하지 않는다.
- `config_audit/comparison.py`: 기존 상태 전이 매핑을 재사용한다. 본 LAB에서는 같은 스키마·규칙으로 저장된 관찰을 재평가하며 기존 STRICT 비교를 수정하지 않는다.
- `api/report_pdf.py`: 기존 한글 폰트·escaping·색상 도구를 재사용한다. 기존 실제 JSON/PDF는 변경하지 않는다.
- 기존 Day2 스크립트의 프로젝트명 `infra-day2-lab`과 Compose의 `scanner-day2`가 다르고 영속 DB를 사용하므로 기존 환경을 수정해 재사용하지 않는다. 별도 `scanner-p2lm`으로 격리한다.
- 기존 미커밋 파일 41개를 비공개 로컬 ZIP과 해시 목록으로 백업했다. 기존 Windows/Network/WEB-WAS JSON/PDF 15개도 해시로 보존 확인한다. 경로는 Codex 작업 디렉터리 `work/pre-linux-mysql-checkpoint/`이며 공개용 자료가 아니다.
- 브랜치 `feature/phase2-linux-mysql`, 기존 HEAD 5724bff에서 분기. commit/push/stash/reset은 수행하지 않는다.

## 내부 개인 LAB 기준

KISA 공식 항목 번호나 인증 기준이 아니다. 규칙 버전은 `LINUX-MYSQL-LAB-0.1`이다. 별도 조직 승인 문서나 독립 기대 해시 부재만으로 LAB PASS를 막지 않는다. 없는 값은 생성하지 않는다.

| 항목 | 실제 관찰 및 양호 조건 | 최초 템플릿 |
|---|---|---|
| LINUX-LAB-001 | sshd -T의 PermitRootLogin=no | yes |
| LINUX-LAB-002 | sshd -T의 PasswordAuthentication=no | yes |
| LINUX-LAB-003 | root 소유 일반 파일, symlink 아님. shadow 0600/0640 및 root/shadow 그룹, 설정 0600/0644 및 root 그룹 | 두 파일 0666 |
| LINUX-LAB-004 | LAB 불필요 서비스 TCP9000 LISTEN 부재 | 무해한 전용 테스트 디렉터리 HTTP 서비스 |
| LINUX-LAB-005 | rsyslog 실행 및 제공한 auth/authpriv 파일 경로 설정, 시작 hash 일치 | auth 로그 stop |
| MYSQL-LAB-001 | mysql.user의 익명 계정 수 0 | 익명 계정 1개 |
| MYSQL-LAB-002 | localhost/127.0.0.1/::1 이외 Host의 root 계정 수 0 | root@% 존재 |
| MYSQL-LAB-003 | 현재 GLOBAL local_infile=0 | 1 |
| MYSQL-LAB-004 | 현재 GLOBAL require_secure_transport=1 | 0 |
| MYSQL-LAB-005 | lab_app@localhost에 lab_data.items SELECT만 직접 부여, 역할/mandatory roles/proxy 없음 | 전역 ALL PRIVILEGES |

기존 LAB-SSH-002, LAB-MYSQL-001/002와 의미가 겹치는 항목은 legacy_check_id로 연결한다. 새 공통 엔진을 만들지 않는다. 확장 결과는 기존 Day2 결과와 별도 스냅샷이다.

SSH 검증 범위는 고정 root/loopback Match 조건이다. 컨테이너의 root 암호를 설정하거나 SSH 로그인 시험을 수행하지 않는다. 설정이 취약해도 계정 잠김 등 다른 방어가 있을 수 있으므로 실제 침해 가능성을 확정하지 않는다. 파일 내용·암호 hash·SSH 개인키는 읽어 내보내지 않는다.

MySQL의 원격 root 기준은 계정 존재 기준이며 잠금/실제 접근 성공을 주장하지 않는다. lab_app 한 계정만 최소 권한 평가한다. 역할이나 알 수 없는 SHOW GRANTS 구조는 NEEDS_REVIEW이고, 다른 범위의 명확한 직접 권한은 FAIL이다. 전체 DB 계정의 최소 권한을 평가했다고 주장하지 않는다.

## 제품 및 실행 범위

- Linux 이미지: `ubuntu:noble-20261024.1` / Ubuntu 24.04. OpenSSH·rsyslog 패키지는 빌드 시 설치하며 실제 버전을 별도 기록한다.
- MySQL 이미지: `mysql:8.4.13` / 8.4 계열. [공식 이미지 목록](https://github.com/docker-library/official-images/blob/master/library/mysql)에서 태그를 확인했다.
- [Ubuntu 공식 이미지 목록](https://github.com/docker-library/official-images/blob/master/library/ubuntu). 태그는 digest 고정이 아니며 실제 image ID를 수집한다. 빌드나 실제 구동은 아직 확인하지 않았다. 가용하지 않으면 latest로 임의 대체하지 않는다.
- 제공 LAB의 Ubuntu 24.04/MySQL 8.4.13만 우선 적용한다. 다른 버전이나 알 수 없는 버전은 NOT_TESTED와 미지원 사유를 기록한다. 미확인 설정은 NOT_TESTED/NEEDS_REVIEW, 수집 실패는 ERROR이다.
- internal bridge 하나, 호스트 포트/host network/bind mount/privileged 없음. 기존 VM, 네트워크, Docker daemon, 전역 방화벽은 수정하지 않는다.
- Linux의 root/제한된 capability는 컨테이너 내부 sshd/rsyslog 실행에만 사용한다. SYS_ADMIN/NET_ADMIN은 부여하지 않는다. 컨테이너는 완전한 VM이나 운영 Linux 전체를 대체하지 않는다.
- Linux 메모리 192MB, MySQL 768MB. MySQL 데이터와 임시 인증 파일은 컨테이너 tmpfs이며 영속 DB나 운영 데이터가 아니다. 정지/재생성 시 데이터·인증 파일을 잃는다.

## 자격증명 보호

사용자가 MySQL 컨테이너를 실행하면 `openssl rand`로 임시 암호를 만들고, 컨테이너 `/run/lab` tmpfs의 제한된 파일에만 저장한다. 코드·Compose 환경변수·Git·호스트 JSON/PDF에 암호를 저장하지 않는다. MYSQL_RANDOM_ROOT_PASSWORD의 암호 로그 출력 기능은 사용하지 않는다. 초기화 스크립트도 SQL/암호를 출력하지 않는다.

수집기는 LAB 내부 로컬 root 소켓으로 고정 SELECT/SHOW 쿼리만 실행한다. `--defaults-extra-file`을 사용하여 CLI 인자에 암호를 전달하지 않는다. 이는 개인 disposable LAB 전용이며 운영 DB 자동화용 계정 설계가 아니다. 사용자 이름/Host 목록, authentication_string, 비밀번호 hash를 수집하지 않는다. 통계와 정규화된 권한 종류만 보존한다. docker inspect의 원문, 자격증명 파일, SQL 원문 결과를 보고서로 출력하지 않는다.

## 1. 최초 실행 및 취약 설정 수집 — 사용자 PowerShell

프로젝트 루트에서 실행한다. 각 명령이 실패하면 다음 단계로 넘어가지 않는다. 기존 LAB Compose를 down/prune하지 않는다.

```powershell
Set-Location C:\Projects\infrastructure-security-scanner-clone
New-Item -ItemType Directory -Force .\logs\phase2-linux-mysql, .\reports\phase2-linux-mysql | Out-Null
.\.venv\Scripts\python.exe -B -m scripts.run_linux_mysql_audit

$env:LINUX_MYSQL_STAGE = 'before'
docker compose -f .\lab\linux-mysql-retest\compose.json config --quiet
docker compose -f .\lab\linux-mysql-retest\compose.json build --pull
docker compose -f .\lab\linux-mysql-retest\compose.json up -d --no-build --wait --wait-timeout 180
docker compose -f .\lab\linux-mysql-retest\compose.json ps
.\.venv\Scripts\python.exe -B -m scripts.run_linux_mysql_audit --execute --output .\logs\phase2-linux-mysql\before.json --pdf .\reports\phase2-linux-mysql\before.pdf
```

기본 명령은 네트워크 없이 NOT_TESTED 10개이다. 실제 최초 JSON에서 FAIL 10개를 확인한 후 개선한다. 현재 FAIL 10개는 합성 테스트의 기대 결과이며 실제 최초 결과가 다르면 실제 결과를 유지하고 원인을 조사한다. 오류나 누락을 FAIL로 조작하지 않는다.

## 2. 컨테이너 내부 개선 — 사용자 PowerShell

Linux만 개선 이미지로 재생성한다. MySQL은 재생성하지 않고 동일 실행 인스턴스에서 고정 LAB 개선 스크립트를 실행한다. 이전 Linux 컨테이너 파일은 교체되므로 먼저 before.json을 확보해야 한다.

```powershell
$env:LINUX_MYSQL_STAGE = 'after'
docker compose -f .\lab\linux-mysql-retest\compose.json build linux
docker compose -f .\lab\linux-mysql-retest\compose.json up -d --no-deps --no-build --force-recreate linux
docker compose -f .\lab\linux-mysql-retest\compose.json exec -T mysql bash /opt/lab/harden-mysql.sh
Start-Sleep -Seconds 3
```

MySQL 스크립트는 명시한 익명 계정/root@%를 삭제하고 lab_app의 전역 권한을 테이블 SELECT로 제한하며 두 GLOBAL 변수를 변경한다. 그 외 계정을 임의로 삭제하지 않는다. SQL 오류 시 일부 변경이 적용됐을 수 있으므로 실제 상태를 재수집한다. 수집기는 이 스크립트를 호출하지 않는다.

MySQL의 변경은 현재 GLOBAL 설정이며 재시작 후 유지되는 운영 설정 변경으로 주장하지 않는다. 컨테이너를 정지/재생성하면 tmpfs 데이터가 사라지고 최초 상태로 초기화될 수 있다. 이 LAB는 즉시 조회→변경→재조회와 원본 JSON 보존을 위한 환경이다.

## 3. 재점검 및 전후 JSON/PDF — 사용자 PowerShell

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_linux_mysql_audit --execute --baseline-json .\logs\phase2-linux-mysql\before.json --output .\logs\phase2-linux-mysql\after.json --pdf .\reports\phase2-linux-mysql\after.pdf
```

같은 논리 자산, 제품/패키지 버전, 규칙, scope, 수집 방법과 정상 시각 순서를 비교한다. 버전 변화·시각 역전은 INCOMPARABLE이며 ERROR/미수집→PASS는 개선 완료로 처리하지 않는다. 실제 FAIL→PASS만 LAB 조치·재점검 관찰로 기록하고 인과관계 전체를 입증했다고 주장하지 않는다. 승인 문서나 독립 해시가 없다는 이유로 이 관찰을 막지 않는다.

이미 파일이 있으면 새 이름 before-v2.json/after-v2.json/after-v2.pdf를 사용한다. CLI는 기존 파일을 덮어쓰지 않는다. 실제 재점검 JSON은 사용자 실행 후 생성하며 이번 오프라인 단계에서 만들어 내지 않는다.

선택적 오프라인 재분석:

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_linux_mysql_audit --input-json .\logs\phase2-linux-mysql\after.json --baseline-json .\logs\phase2-linux-mysql\before.json --output .\reports\phase2-linux-mysql\offline.json --pdf .\reports\phase2-linux-mysql\offline.pdf
```

원본 collected_at은 유지하고 checked_at/generated_at은 재분석 시각으로 구분한다. 재분석을 새 컨테이너 시험으로 주장하지 않는다. JSON의 bundle은 정규화된 최소 관찰값이며 원본 설정/로그/자격증명을 포함하지 않는다. 증적 참조의 SHA-256은 정규화된 관찰 바이트의 식별자이고 독립 무결성 인증이 아니다. baseline 파일의 실제 SHA-256도 별도 기록한다.

## 범위와 아직 필요한 실제 검증

- 이미지 pull/build, tmpfs DB 초기화와 메모리 한도, 실제 패키지 버전/프로세스 기동.
- 실제 sshd -T 결과, 파일 소유자/권한, TCP9000 상태, rsyslog 설정과 프로세스, MySQL 쿼리 성공 및 실제 FAIL→PASS.
- rsyslog의 실제 보안 이벤트 수신·보존은 이번 설정 진단 PASS와 별도이다.
- require_secure_transport=ON은 TLS TCP 또는 Unix 소켓 등 안전한 전송을 요구하는 설정이다. 로컬 소켓 쿼리 성공은 실제 TCP TLS/인증서 검증 성공 증거가 아니다.
- SSH 실제 로그인, PAM/GPO 같은 외부 정책, systemd 전체 서비스, 운영 네트워크 노출, 다른 DB 사용자 권한은 검증하지 않는다.
- 기존 WEB/WAS 실제 완료 사실은 사용자의 실습 결과로 보존하며 이 LAB의 합성 결과와 섞지 않는다.

## 테스트 및 오류 대응

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_linux_mysql_lab
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
docker compose -f .\lab\linux-mysql-retest\compose.json ps -a
docker compose -f .\lab\linux-mysql-retest\compose.json logs --tail 40
```

Docker context는 로컬 default/desktop-linux만 허용하며 foreign 프로젝트, host network, 외부 endpoint, 허용되지 않은 mount/capability/호스트 포트를 거부한다. raw Docker 오류나 SQL 오류 본문 대신 고정 코드만 반환한다. 이미지 가용성이나 자원 부족 시 검사값을 추정하지 않는다. 기존 Git Bash 초기화 회귀 실패는 별도 환경 문제로 기록하고 테스트를 건너뛰지 않는다.

실습 종료는 이 LAB만 종료한다. tmpfs DB/인증 파일이 사라지므로 JSON/PDF를 먼저 보존한다.

```powershell
docker compose -f .\lab\linux-mysql-retest\compose.json down
Remove-Item Env:LINUX_MYSQL_STAGE -ErrorAction SilentlyContinue
```

## 제품 문서

- [OpenSSH sshd -T/-C](https://man.openbsd.org/sshd.8)
- [MySQL 8.4 시스템 변수/require_secure_transport](https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_require_secure_transport)
- [MySQL 역할](https://dev.mysql.com/doc/refman/8.4/en/roles.html)
- [공식 MySQL 이미지 초기화 코드](https://github.com/docker-library/mysql/blob/master/8.4/docker-entrypoint.sh)

제품 문서는 지시어/변수 의미를 확인하는 출처이며, 여기서 사용하는 양호 기준은 프로젝트의 개인 실습 기준이다.
