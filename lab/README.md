# 격리 실습 실행 가이드 (2026-10)

이 문서는 실행 재현을 위한 지침입니다. **사용자 소유 EC2에서 실행했다는 증거는 아닙니다.**
운영 서버 SSH 설정·운영 데이터·기존 MySQL을 변경하지 않습니다.

## 1. 사전 준비

- Python 3.12, Docker Compose v2. 실행 대상은 직접 소유·승인된 루프백이나 SSM 전송 포트만 사용합니다.
- `lab/compose.yml`은 실습 서비스를 **127.0.0.1**에만 바인딩합니다. EC2 Security Group에 실습 포트를 열지 마세요.
- 이미지: `python:3.12.7-slim-bookworm`, `mariadb:10.11.10`, DVWA 공식 `068d974` 이미지 **멀티 아키텍처 digest 고정**. Python 베이스와 MariaDB는 정확한 태그이나 digest 고정은 아닙니다. 실제 이미지 ID는 `docker image inspect`로 기록하세요.
- 앱 스캐너 MySQL은 기존 `docker/docker-compose.yml`의 별도 DB를 사용합니다. DVWA의 MariaDB 데이터와 절대 합치지 마세요.

로컬 단기 암호를 터미널 환경변수로만 전달하고 작업을 마치면 제거하세요. SSH 개인키는 GitHub/노션에 올리지 않습니다.

```bash
export LAB_SSH_PASSWORD="$(openssl rand -hex 24)"
export DVWA_DB_ROOT_PASSWORD="$(openssl rand -hex 24)"
export DVWA_DB_PASSWORD="$(openssl rand -hex 24)"
# 베이스라인만: 
docker compose -f lab/compose.yml --profile baseline up -d --build
# 취약 실습은 별도 사용자 소유 호스트 또는 격리 CI에서만:
docker compose -f lab/compose.yml --profile vulnerable up -d --build
docker compose -f lab/compose.yml --profile baseline --profile vulnerable ps
```

두 프로파일을 하나의 호스트에서 동시에 실행하면 서로 다른 포트가 사용됩니다.

| 검사 | 정상 로컬 포트 | 취약 실습 포트 | 기대 비교 (미실행시 미확정) |
|---|---:|---:|---|
| FTP anonymous | 2121 | 2122 | 530 거부 / 230 성공 |
| SSH auth policy | 2222 | 2223 | 비밀번호 비활성 / 활성 (취약 CVE 확정 아님) |
| HTTP headers | 8081 | 8082 | 적용 / 일부 미적용 |
| 입력값으로 사용자 조회 | 8081/lookup | DVWA 4280/vulnerabilities/sqli/ | 매개변수화 SQL / 취약 DVWA 읽기 |
| DVWA | 미구축 | 4280 | 정상 로컬에서 DVWA 미구축은 안전 판정 아님 |

실제 IP, 포트 및 인증 정책을 허가된 `config/scope.local.json`에 반영한 다음 스캔합니다. 실습 서비스는 컨테이너에서 격리되며, 운영 SSH 포트 22는 수정하지 않습니다.

## 2. V7 DB 이전 (기존 이력 보존)

현재 적용된 DB가 V6이고 외부 백업이 있는지 먼저 확인하세요. 아래는 **적용하는 실제 명령**이므로 사용자 자신의 환경에서 검증 후 실행합니다.

```bash
docker exec portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump -uroot --single-transaction port_scan' > "port_scan_backup_$(date +%Y%m%d).sql"
docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot' < sql/migration_v7.sql
```

마이그레이션은 `lab_verification_results`만 추가합니다. 삭제·재설정 마이그레이션을 실행하지 않습니다. FK 오류·미적용 상태를 확인하려면 별도 테스트 DB를 이용하세요.

## 3. 스캔 후 승인 범위에 따른 점검

먼저 실제 포트 스캔을 실행해 DB에 scan ID를 기록합니다.

```bash
python -m scripts.run_scan scan -sT -sV --target 127.0.0.1 --ports 2121,2222,8081 --scope-file config/scope.local.json --max-workers 4
python -m scripts.run_lab_verification --scan-id 1 --environment LOCAL_BASELINE --scope-file config/scope.local.json --dry-run
python -m scripts.run_lab_verification --scan-id 1 --environment LOCAL_BASELINE --scope-file config/scope.local.json --allow-ftp-anonymous
```

위 `1`을 **실제 생성된** ID로 대체합니다. FTP 로그인 검사는 플래그로 명시적으로 허용해야 합니다. FTP 파일 조작은 하지 않습니다.

SSH 인증 정책은 배너만으로 증명할 수 없으며, 관리자 승인 하에 각 **실습 컨테이너의** `sshd -T`와 런타임 `sshd` 명령행을 확인한 후 별도 로컬 JSON 파일로 제공합니다. 운영 SSH에 대한 `sshd -T`를 실습 증적으로 잘못 사용하지 마세요.

```bash
docker compose -f lab/compose.yml exec -T ssh-safe /usr/sbin/sshd -T -o PasswordAuthentication=no
docker compose -f lab/compose.yml exec -T ssh-weak /usr/sbin/sshd -T -o PasswordAuthentication=yes
```

## 4. DVWA 및 Nuclei

DVWA 초기 데이터 생성은 **새로 만든 일회용 DVWA MariaDB**에서만 합니다. 이미 데이터가 들어 있는 DVWA에서 `Create / Reset Database`를 자동으로 실행하지 마세요. 최초 설정 절차는 공식 `/setup.php`를 확인하세요.

DVWA 계정은 로컬 환경변수 `DVWA_USERNAME`, `DVWA_PASSWORD`로 전달하고, 검증 결과에 저장하지 않습니다. SQLi는 파괴적인 쿼리 없이 특정 사용자 조회의 반환 행 수 차이를 비교합니다. 일반 업무 데이터베이스에 사용하지 마세요.

```bash
python -m scripts.run_lab_special --check DVWA_SQLI --scan-id 2 --port-id 123 --environment EC2_LAB --scope-file config/scope.aws.local.json
```

Nuclei 공식 실행 파일은 사용자 로컬에 설치하고 SHA-256을 확인하세요. 실습 템플릿의 SHA는 **파일 내용 기준**으로 계산합니다. Nuclei 매칭은 `POTENTIAL`까지만 반영됩니다.

```bash
sha256sum lab/nuclei/missing-nosniff.yaml
python -m scripts.run_lab_special --check NUCLEI --scan-id 2 --port-id 124 --environment EC2_LAB --scope-file config/scope.aws.local.json --nuclei-binary /absolute/path/to/nuclei --template-root lab/nuclei --template-name missing-nosniff.yaml --template-sha256 <해시>
```

## 5. 비교 보고서

```bash
python -m scripts.generate_integrated_lab_report --local-scan-id 1 --ec2-scan-id 2 --format both --output-dir reports
```

기존 V6 자산/CVE 보고서와 V7 실습 기록을 하나의 일관된 DB 스냅샷에서 조회해 JSON과 PDF로 출력합니다. 서로 다른 스캔 ID를 입력합니다. 단, `ports` 테이블은 포트의 현재 행을 재사용하므로 동일 자산의 동일 포트를 재스캔하면 과거 버전·배너를 완전 재현하지 못합니다. 재점검 증적은 V7 별도 관찰 이력으로 관리합니다.

## 6. EC2 접근 제어

이미 존재하는, 승인받은 EC2에만 `vulnerable` 프로파일을 실행합니다. 퍼블릭 IP나 `0.0.0.0:PORT`로 실습 서비스를 열지 않습니다. Instance Profile/SSM을 선호하며 AWS 액세스 키는 저장하지 않습니다.

인스턴스의 SSM 관리가 구성돼 있다면 작업자 PC에서 포트별로 다음 명령을 사용합니다. 예시 인스턴스 ID를 실제 승인된 값으로 바꾸세요.

```bash
aws ssm start-session --target i-EXISTING-APPROVED-INSTANCE --document-name AWS-StartPortForwardingSession --parameters '{"portNumber":["4280"],"localPortNumber":["4280"]}'
```

SSH 운영 데몬, Security Group, IAM 권한을 변경하는 명령은 제공하지 않았습니다. 별도 리소스 생성·과금·네트워크 규칙 변경은 승인 전 수행하지 않습니다.

## 검증 분류

- **단위 테스트 통과**: 모의 네트워크/DB에서 코드를 실행했다는 뜻입니다.
- **Docker CI 통과**: GitHub Actions의 일회용 로컬 컨테이너에서 실제 요청·DB 쓰기·보고서를 확인했다는 뜻입니다. **EC2 검증이 아닙니다.**
- **EC2 실측**: 승인된 실제 EC2에서 수행한 별도 로그·증적 해시가 있을 때만 표시합니다.

현재 각 실행의 최신 상태는 GitHub Actions `격리 실습 통합 검증` 워크플로에서 확인하세요. 성공하지 않은 단계는 완료로 표시하지 않습니다.


## 기존 EC2에서의 실제 검증 — 사용자 실행 단계

[EC2 실측 실행 지침](../docs/ec2_execution_plan.md)의 사전 검사, IMDSv2 기반 배포 게이트, 사용자 PC SSM 포트 전달 검사, 개선 후 재점검, JSON/PDF+SSM manifest 비교 순서대로 진행하세요. EC2(t3.micro)는 1GiB RAM이므로 기본 자원 기준에 미달할 수 있습니다. 승인 없는 비용 변경·운영 SSH 변경·인터넷 공개는 하지 않습니다. 실제 EC2 SSM 실측은 아직 수행되지 않았습니다.
