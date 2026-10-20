# 승인된 격리 실습 검증 — V7 개발 및 실제 테스트

**증적 범위:** 2026-10-20 GitHub Actions의 일회용 Ubuntu Docker 컨테이너에서 실행한 결과입니다. 실제 사용자 소유 AWS EC2에서는 접속·배포·진단을 하지 않았습니다. EC2 Security Group, 운영 SSH, IAM 또는 과금 리소스를 변경하지 않았습니다.

## 실제 Docker 통합 테스트

- [실제 Docker 통합 검증 성공](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39415402659)
- [자동 회귀 테스트 성공](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39415402660)
- 격리된 MySQL 8.0.40에 기존 V6 구조를 적용하고 데이터 1건을 저장한 뒤 V7 마이그레이션을 적용했습니다. 이전 스캔이 남아 있음을 확인했습니다.
- `lab/compose.yml`의 FTP, SSH, HTTP, DVWA, MariaDB 실습 서비스를 loopback에 바인딩했습니다.
- DVWA 초기 사용자 데이터 5건을 실습용 MariaDB 쿼리로 확인한 후 로그인과 비파괴 SQL Injection 결과 행 증가를 재현했습니다.
- Nuclei 공식 v3.11.1 배포 파일 SHA-256을 확인한 뒤 `lab/nuclei/missing-nosniff.yaml`을 실행하고 JSONL 결과를 `POTENTIAL`로 저장했습니다.
- V7에 실행 상태, 설정 판정, 증적 SHA-256을 분리 저장했습니다. 다른 ID인 정상 스캔 `2`와 취약 실습 스캔 `3`을 하나의 `REPEATABLE READ` DB 스냅샷에서 보고서 JSON/PDF로 생성했습니다.
- 보고서의 `NOT_TESTED`는 서비스가 없거나 검증되지 않았다는 뜻이며 안전 판정이 아닙니다.

| 점검 | 정상 컨테이너 | 취약 컨테이너 | 의미 |
|---|---|---|---|
| FTP 익명 인증 | `NOT_DETECTED` | `CONFIRMED` | 익명 로그인 설정 확인, CVE 확정 아님 |
| SSH 비밀번호 인증 | `NOT_DETECTED` | `POTENTIAL` | 격리 실습의 인증 정책 비교; 공격/대입 없음 |
| HTTP 헤더 | `NOT_DETECTED` | `POTENTIAL` | 검사 대상 헤더 누락, 개별 적용 타당성 검토 필요 |
| DVWA SQL Injection | 정상 서비스와 별도 구성 | 실제 재현 | 격리된 초기 데이터에 대한 읽기 전용 조회 결과 확대 |
| Nuclei 템플릿 | 별도 스캔 미실행 | 매칭 `POTENTIAL` | 매칭만으로 CVE 확정 금지 |

정상 SQL 조회 서비스는 `lab/server.py`의 파라미터 바인딩 코드를 사용합니다. 정상 서비스에 DVWA가 없다는 사실을 SQL Injection 안전 증명으로 사용하지 않습니다. 각 검사별 증적은 다운로드 가능한 GitHub Actions 아티팩트와 V7 이력에 남습니다.

## 사용자 로컬/EC2 재현

프로젝트 루트에서 다음 명령을 사용합니다. 각 `<SCAN_ID>`, `<PORT_ID>`는 실제 DB에서 생성된 값으로 대체하고, `scope.local.json`과 인증정보는 **Git에 커밋하지 않습니다.**

```bash
# (1) 설정된 승인 범위만 dry-run
python -m scripts.run_lab_verification --scan-id <SCAN_ID> --environment LOCAL_BASELINE --scope-file config/scope.local.json --dry-run

# (2) FTP 인증을 명시적으로 승인한 실습 환경 점검
python -m scripts.run_lab_verification --scan-id <SCAN_ID> --environment LOCAL_BASELINE --scope-file config/scope.local.json --allow-ftp-anonymous

# (3) 이력과 설정 결과를 별도의 두 스캔 ID로 통합
python -m scripts.generate_integrated_lab_report --local-scan-id <LOCAL_SCAN_ID> --ec2-scan-id <EC2_SCAN_ID> --output-dir reports --format both
```

Nuclei/DVWA 검증 경로는 `scripts.run_lab_special`; Docker 실습 구성, 초기 DB 백업 및 SSM 포트 전달은 [lab/README.md](../lab/README.md)를 확인하세요. Nuclei는 템플릿 SHA-256 allowlist가 일치해야 하며 실제 프로세스 실패는 `ERROR/INCONCLUSIVE`입니다. DVWA는 초기화된 격리 데이터만 사용하고 사용자/운영 DB를 수정하지 않습니다.

**판단 규칙:** `execution_status=SUCCESS`는 검사 실행 성공을 뜻하고 `finding_status=CONFIRMED`는 해당 설정 또는 실습 동작이 실제 재현됐다는 뜻입니다. CVE 결과/우선순위는 기존 V6 파이프라인과 별도로 유지합니다. SHA-256은 동일한 증적 내용 확인 수단이지 전자서명이나 출처 진정성 증명은 아닙니다.

## 남은 과제

- 사용자 소유 EC2 SSM/VPN 등 안전한 접근이 확보된 후 취약 컨테이너 실제 배포, 재점검 및 장비별 증적 비교. 실제 EC2는 **미검증**입니다.
- EC2 운영 SSH 설정을 바꾸지 않고, **컨테이너 실습 SSH만** 관리자 정책·실행 옵션을 확인해야 합니다.
- 이미지 중 일부는 버전 태그로 고정돼 있고 모든 이미지가 digest 고정된 것은 아닙니다. 실제 이미지 digest를 기록해야 합니다.
- **조치 후 재점검 성공:** Docker CI에서 `http-weak` 서비스의 누락 보안 헤더를 적용한 컨테이너로만 재생성하고, 동일 자산/포트의 V7 이력에 `POTENTIAL → NOT_DETECTED`를 각각 저장한 뒤 JSON 보고서에서 두 상태가 모두 유지되는지 확인했습니다. 이 조치는 **GitHub Actions 일회용 컨테이너**에만 적용했습니다. [검증 완료 CI](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39415844206).
- 실제 실행 중인 두 SSH 실습 컨테이너의 sshd 프로세스 인수에서 `PasswordAuthentication=no/yes`를 각각 읽어 비교했습니다. 사용자 EC2의 SSH 인증 정책을 확인한 결과는 아닙니다.
- 별도 자동 회귀 테스트 **269개**가 통과했습니다. [CI 실행 기록](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39415844259).
