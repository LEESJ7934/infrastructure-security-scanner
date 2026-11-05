# 2일차 개발 결과

## 1. 수행 범위와 격리 환경

Ubuntu 24.04와 MySQL 8.0을 Docker Compose로 구성하고, 로컬 실습 컨테이너에서 유효 설정을 읽어 기존 공통 설정 진단 엔진으로 평가했다. 실제 실습은 Compose 프로젝트 이름을 `infra-day2-lab`으로 지정해 수행했다. Compose 파일의 기본 프로젝트 이름은 `scanner-day2`다.

두 서비스는 프로젝트 전용 내부 네트워크를 사용한다. 신규 호스트 포트 공개와 호스트 디렉터리 마운트 없이 구성했으며, MySQL 데이터는 전용 이름 있는 볼륨에 저장한다. 기존 `portscan-mysql`과는 컨테이너, 네트워크, 데이터 볼륨이 분리돼 있다. Ubuntu 이미지는 빌드 단계에서 OpenSSH 서버 패키지를 설치하며 SSH 데몬을 기본으로 시작하지 않는다.

## 2. 신규 파일과 구현 내용

| 파일 | 구현 내용 |
|---|---|
| [config_audit/collectors/linux_ssh.py](../../config_audit/collectors/linux_ssh.py) | `sshd -T`의 유효 설정에서 `maxauthtries`, `permitrootlogin`, `passwordauthentication`, `x11forwarding`, `permitemptypasswords`를 읽는다. 항목 누락과 파싱 오류를 구분한다. |
| [config_audit/collectors/mysql_config.py](../../config_audit/collectors/mysql_config.py) | 컨테이너 내부 Unix 소켓에서 고정된 읽기 전용 `SELECT`로 버전과 `local_infile`, `require_secure_transport`, `skip_name_resolve`, `general_log`를 조회한다. 실습에서 확인한 버전은 8.0.44다. |
| [scripts/run_day2_audit.py](../../scripts/run_day2_audit.py) | `--execute` 승인 후 로컬 Docker Desktop 엔진에서 프로젝트·서비스 라벨과 실행 상태·이름을 확인하고 해당 컨테이너 ID로만 수집한다. 관찰값을 기존 `config_audit` 엔진에 전달해 실습 기준 4개를 평가한다. 출력에는 허용된 관찰값과 안전하게 직렬화한 결과만 담으며, 수집 실패는 고정된 오류 코드로 표시한다. |
| [tests/test_day2_audit.py](../../tests/test_day2_audit.py) | Docker 호출을 모의 처리해 파싱, 판정, 수집값 누락, 시간 초과, 대상 거부, 민감정보 출력 방지를 검증하는 단위 테스트 11개를 추가했다. |
| [lab/day2/](../../lab/day2/) | `compose.yaml`, `ubuntu/Dockerfile`, `.env.example`, `.gitignore`, `README.md`로 실습 환경과 사용 절차를 정의한다. |

## 3. 실제 자동 진단 결과

사용자가 실제 Docker 실습 컨테이너에서 Ubuntu의 `PermitRootLogin`을 `without-password`에서 `no`로, MySQL의 `require_secure_transport`를 `0`에서 `1`로 변경했다. 이후 Python 진단기를 다시 실행한 결과, 두 항목 모두 `FAIL`에서 `PASS`로 바뀌었다. 수집기는 설정 조회와 판정을 수행하며 설정 변경은 실습 중 별도로 수행했다.

| 실습 기준 | 기대 조건 | 개선 전 | 개선 후 |
|---|---|---|---|
| `LAB-SSH-001` | `PermitEmptyPasswords = no` | PASS | PASS |
| `LAB-SSH-002` | `PermitRootLogin = no` | FAIL | PASS |
| `LAB-MYSQL-001` | `local_infile = 0` | PASS | PASS |
| `LAB-MYSQL-002` | `require_secure_transport = 1` | FAIL | PASS |

## 4. 증적과 테스트

저장소 루트 기준 증적 경로는 개선 전 `logs/day2-before.json`, 개선 후 `logs/day2-after.json`이다. 두 파일은 `logs/`의 Git 제외 규칙을 적용받는다. 문서 작성 시 두 파일에서 점검 ID와 판정만 대조했으며, 위 표의 결과와 일치했다.

신규 단위 테스트 11개는 Codex에서 통과했다. 이전 Codex 전체 실행에서는 기존 Git Bash 초기화 및 루프백 연결 제한으로 5개가 실패했다. 이후 사용자가 Windows PowerShell에서 기존 348개와 신규 11개를 포함한 **전체 359개 테스트 통과**를 확인했다. 문서 작성 중에는 테스트나 컨테이너 진단을 다시 실행하지 않았다.

## 5. 기술적 제한사항

- 자동 판정은 Linux 2개와 MySQL 2개로 총 4개다. 당초 계획한 Linux 6개 중 나머지 4개와 MySQL 9개 중 나머지 7개는 미구현이다. `LAB-*`는 실습용 식별자이며 공식 KISA 점검항목 번호가 아니다.
- Ubuntu 컨테이너에서 관찰한 SSH 유효 설정은 실제 VM의 부팅, 서비스 운영, 접근 제어를 포함한 전체 보안 진단으로 확대할 수 없다. 컨테이너 내부에서 변경한 SSH 설정은 컨테이너 재생성 시 사라질 수 있다.
- MySQL의 `SET PERSIST` 설정은 같은 실습 데이터 볼륨을 사용하는 동안 유지된다. `require_secure_transport`의 값은 서버 정책을 확인한 결과다. 수집기는 내부 Unix 소켓을 사용하므로 TLS 인증서, 클라이언트의 TLS 협상 및 실제 외부 연결은 별도 검증이 필요하다.
- 개선 전후 JSON은 독립적으로 실행한 결과를 비교한 것이다. DB 기반 재점검 이력, 자동 증적 연결, 보고서 통합은 미구현이다.
- 현재 실행기는 이름과 라벨이 일치하는 로컬 실습 서비스로 범위가 한정된다. 원격 자산 수집에 필요한 기존 `ScopePolicy.authorize()` 연결은 미구현이다.

## 6. 후속 작업

1. Linux·MySQL의 미구현 점검 항목을 확대하고 제품·버전별 적용 조건을 정리한다.
2. 점검별 증적과 개선대책을 연결하고 공식 기준을 적용할 수 있는 범위를 항목별로 검토한다.
3. Suricata, ModSecurity, OPNsense 설정 수집을 연계한다.
4. DB 기반 재점검 이력과 보고서를 통합한다.
