# Linux 및 MySQL 보안 설정 기초 실습

승인된 로컬 환경에서 보안 설정을 수집하고, 같은 대상의 취약 설정과 개선 설정을 비교하기 위한 실습 환경이다.

- **Ubuntu 24.04**에는 이미지 빌드 단계에서 `openssh-server`를 설치한다. 기본 명령은 `sleep infinity`이며 SSH 데몬을 시작하지 않는다. 이미지에는 SSH 호스트 키를 남기지 않는다. 향후 `sshd -T`로 유효 설정을 확인할 때 호스트 키나 런타임 디렉터리가 필요하면 실습 컨테이너 안에서 준비한다.
- **MySQL 8.0**은 공식 `mysql:8.0` 이미지를 사용한다. 상태 검사는 컨테이너 내부에서 TCP로 접속해 `SELECT 1`을 실행한다. 데이터는 Day 2 프로젝트의 전용 이름 있는 볼륨에 보관한다.

## 환경변수 설정

저장소 루트에서 PowerShell로 다음을 실행한다.

```powershell
Set-Location lab/linux-mysql-foundation
Copy-Item .env.example .env
```

`.env`를 편집해 `MYSQL_ROOT_PASSWORD`에 비어 있지 않은 실습 전용 비밀번호를 입력한다. `.env`는 Git 추적 대상에서 제외된다. PowerShell에 같은 이름의 환경변수가 이미 있으면 Compose가 그 값을 우선하므로, 이 실습용 `.env`를 사용하려면 실행 전에 해당 세션 변수를 해제한다. 초기화된 MySQL 볼륨의 비밀번호는 `.env`를 바꾸는 것만으로 변경되지 않는다.

## 실행과 상태 확인

아래 명령은 실제 실습을 시작할 때 `lab/linux-mysql-foundation`에서 실행한다. 첫 실행에서는 이미지 다운로드와 Ubuntu 패키지 설치를 위해 빌드 환경의 외부 연결이 필요할 수 있다. 실행 중인 서비스는 내부 전용 네트워크에 연결된다.

```powershell
docker compose -p scanner-day2 --env-file .env -f compose.yaml config --quiet
docker compose -p scanner-day2 --env-file .env -f compose.yaml up -d --build
docker compose -p scanner-day2 --env-file .env -f compose.yaml ps
```

`ps`에서 MySQL이 `healthy`인지 확인한다. 렌더링된 Compose 설정에는 비밀번호가 포함될 수 있으므로 설정 검증에는 `--quiet`를 사용한다.

## 종료와 실습 데이터 삭제

다음 명령은 Day 2 컨테이너와 네트워크를 제거하고 MySQL 데이터 볼륨을 보존한다.

```powershell
docker compose -p scanner-day2 --env-file .env -f compose.yaml down
```

Day 2의 MySQL 데이터까지 초기화해야 할 때만 다음 명령을 사용한다. 이 프로젝트의 실습 볼륨에 저장된 데이터가 삭제된다.

```powershell
docker compose -p scanner-day2 --env-file .env -f compose.yaml down --volumes
```

## 기존 환경과의 분리

두 서비스는 `scanner-day2` 프로젝트가 관리하는 내부 전용 네트워크만 사용한다. 호스트 포트를 게시하거나 호스트 디렉터리를 마운트하는 설정은 없다. MySQL 볼륨도 이 프로젝트가 소유하며 기존 `portscan-mysql` 컨테이너, 네트워크 및 볼륨과 연결하지 않는다. 위 명령에서 프로젝트 이름과 Compose 파일을 모두 지정해 종료나 데이터 삭제 범위를 Day 2로 한정한다.

## 컨테이너와 실제 VM의 차이

이 환경으로 컨테이너 내부의 파일, 서비스 설정, DB 변수와 수집·판정 흐름을 검증할 수 있다. Ubuntu 컨테이너는 호스트 커널을 공유하며 기본 프로세스가 `sleep`이므로 VM의 부팅·서비스 관리, 실제 SSH 접속 제어, 호스트 방화벽이나 커널 보안 상태의 검증은 별도의 승인된 VM에서 수행해야 한다.
