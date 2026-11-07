# Linux/MySQL 실제 실행 오류 복구와 격리 재검증

## 확인된 오류 원인

1. 최초 `before/rsyslog.conf`는 `auth,authpriv.* stop`만 있어 활성 출력 action이 전혀 없었다. 실제 rsyslog 8.2312.0이 `there are no active actions configured`, 오류 `-2103`으로 종료했다. supervisor가 필수 프로세스 종료를 감지하고 sshd도 종료하여 Linux 컨테이너가 Exited(1)이 됐다.
2. 이전 수집기는 실행 여부·privileged·host namespace·포트 공개를 하나의 `unsafe_container_rejected` 코드로 묶었다. 재현에서는 `linux_container_not_running`으로 원인을 좁혔고 위 종료 로그를 확인했다. 안전성 검사를 통째로 해제하지 않았다.
3. 개선된 기존 Linux는 정상 실행 중이어서 사용자가 보낸 inspect의 6개 안전 조건은 모두 정상이었다. 이 현재 inspect만으로 과거 컨테이너가 정상 실행 중이었다고 추정하지 않았다. 최초 오류 경로는 새 replay LAB에서 직접 재현됐다.
4. 최초 JSON이 없는데 비교가 먼저 실패하여 `input_unreadable_or_invalid_json`이 발생했다. 기존 CLI는 비교/PDF 이후 JSON을 저장해 현재 상태까지 잃을 수 있었다.

## 수정 내용

- 최초 rsyslog에 `user.*` 비보안 로그 출력만 추가했다. `auth,authpriv.* stop`은 유지하므로 보안 로그 설정은 여전히 FAIL이다. 취약 조건을 양호 조건으로 바꾸어 테스트를 통과시키지 않았다.
- 시작 전 `sshd -t`, `rsyslogd -N1` 검사, 단기 daemon 종료 검사와 ready marker를 추가했다.
- Linux healthcheck가 sshd/rsyslogd 및 ready marker를 확인하도록 두 Compose에 추가했다. running 직후만 보고 실습 준비 완료로 판단하지 않는다.
- 안전성 실패를 서비스별 stopped/privileged/network/PID/IPC/published port 코드로 분리했다. 누락된 필드는 안전하다고 추정하지 않는다.
- Compose project/service label, 고정 네트워크와 endpoints, 허용 capability/entrypoint, image 이름/ID 및 container ID를 검사한다. image ID는 동일 바이트 식별이며 이미지 출처 진위 인증은 아니다.
- MySQL tmpfs의 `/var/run/mysqld` 및 정규화된 `/run/mysqld`만 같은 허용 경로로 취급한다. bind mount/volume이나 다른 경로를 허용하지 않는다. 이는 이식성 보완이며 이번 최초 종료 오류의 원인이라고 주장하지 않는다.
- 기준 JSON이 없거나 잘못되면 `comparison.status=UNAVAILABLE`과 사유를 기록하고 **현재 수집 JSON은 저장**한다. baseline을 생성·대체하지 않는다.
- JSON을 선택적 PDF보다 먼저 exclusive create로 저장한다. PDF 실패 시 `json_saved=true` 여부를 보고한다. 기존 출력은 덮어쓰지 않는다.
- 고정 profile `current`/`replay`만 허용한다. 서로 다른 프로젝트를 같은 자산으로 비교하지 않는다.

## 기존 개선 후 상태 보존 — 실제 완료

사용자 PowerShell에서 컨테이너 변경 없이 수집했다.

- JSON: `logs/phase2-linux-mysql/current-after-20261106-214155.json`
- PDF: `reports/phase2-linux-mysql/current-after-20261106-214155.pdf`
- 실제 결과: Linux PASS 5개, MySQL PASS 5개. 비교는 요청하지 않았다.
- JSON SHA-256: `da941035c328a6ef51efb14aa043b0a3c669af5f9d59124e1e90d1193ff03799`

이 결과를 최초 FAIL 증적으로 바꾸지 않았다. 원래 `before.json`이 없으므로 원래 프로젝트의 과거 FAIL→PASS 비교를 만들어 내지 않는다. 새 현재 상태를 저장하는 명령:

```powershell
Set-Location C:\Projects\infrastructure-security-scanner-clone
New-Item -ItemType Directory -Force .\logs\phase2-linux-mysql, .\reports\phase2-linux-mysql | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
.\.venv\Scripts\python.exe -B -m scripts.run_linux_mysql_audit --execute --output ".\logs\phase2-linux-mysql\current-after-$stamp.json" --pdf ".\reports\phase2-linux-mysql\current-after-$stamp.pdf"
```

과거 baseline이 필요하더라도 누락된 baseline을 지정하지 않고 현재 상태부터 저장한다. 재시작이나 재생성은 필요하지 않다.

## 새로 재현한 격리 LAB — 실제 검증 기록

별도 프로젝트 `scanner-p2lm-replay`, 별도 internal bridge `scanner-p2lm-replay_isolated`, 별도 image tag를 사용했다. 기존 `scanner-p2lm`, Windows/Network/WEB-WAS 컨테이너와 네트워크는 변경하지 않았다. 아래 재현 자료는 과거의 원본 baseline이 아니다.

| 단계 | JSON | 실제 결과 |
|---|---|---|
| 새 재현 최초 상태 | logs/phase2-linux-mysql-replay/before-v1.json | FAIL 10 |
| 같은 replay 개선 후 | logs/phase2-linux-mysql-replay/after-v1.json | PASS 10 / IMPROVED_OBSERVED 10 |

- before 수집 시각: `2026-11-06T12:46:36.801461+00:00`
- after 수집 시각: `2026-11-06T12:47:37.178136+00:00`
- before SHA-256: `e733dfdd6d6337cded03357af6ee97693c7a819629973ee1bcf3e16634248659`
- after SHA-256: `47b30b38ff3390ccacb95ab42ada8cab3600691765011d8f3c33cb7ef24abeca`
- PDF: `reports/phase2-linux-mysql-replay/before-v1.pdf`, `after-v1.pdf`
- 저장된 JSON의 오프라인 재분석에서도 FAIL 10→PASS 10, 비교 문제 없음을 확인했다. 수집 시각은 변경하지 않았다.
- 실제 Docker 명령은 사용자 PowerShell에서 실행했다. Codex의 Docker 직접 조회는 `docker_query_failed`였으며, 로컬 저장 결과와 사용자 출력을 확인했다.

JSON/PDF에 `new_reproduction_not_historical_baseline`과 새 재현 범위를 기록한다. 해시는 파일 식별·보존 확인이며 수집 출처의 진위나 완전성을 증명하지 않는다.

## 최초 설정 재현 명령 — 기존 LAB 유지

아래는 실제 사용한 절차이다. 이미 before-v1/after-v1 증적을 확보했으므로 다시 실행할 필요는 없다. 재실행할 경우 새 출력 파일명을 사용하고, replay 컨테이너의 현재 상태를 먼저 저장한다.

```powershell
New-Item -ItemType Directory -Force .\logs\phase2-linux-mysql-replay, .\reports\phase2-linux-mysql-replay | Out-Null
$env:LINUX_MYSQL_STAGE = 'before'
docker compose -f .\lab\phase2-linux-mysql\compose.replay.json build
docker compose -f .\lab\phase2-linux-mysql\compose.replay.json up -d --no-build --wait --wait-timeout 180
.\.venv\Scripts\python.exe -B -m scripts.run_linux_mysql_audit --execute --lab-profile replay --output .\logs\phase2-linux-mysql-replay\before-v1.json --pdf .\reports\phase2-linux-mysql-replay\before-v1.pdf
```

처음 실패했던 replay에서는 MySQL을 유지하고 수정한 Linux만 `up -d --no-deps --no-build --force-recreate --wait --wait-timeout 60 linux`로 재생성했다. 어떤 단계에서도 기존 `scanner-p2lm`을 down/restart하지 않았다.

## 개선 및 재점검 명령 — replay만 변경

```powershell
$env:LINUX_MYSQL_STAGE = 'after'
docker compose -f .\lab\phase2-linux-mysql\compose.replay.json build linux
docker compose -f .\lab\phase2-linux-mysql\compose.replay.json up -d --no-deps --no-build --force-recreate --wait --wait-timeout 60 linux
docker compose -f .\lab\phase2-linux-mysql\compose.replay.json exec -T mysql bash /opt/lab/harden-mysql.sh
.\.venv\Scripts\python.exe -B -m scripts.run_linux_mysql_audit --execute --lab-profile replay --baseline-json .\logs\phase2-linux-mysql-replay\before-v1.json --output .\logs\phase2-linux-mysql-replay\after-v1.json --pdf .\reports\phase2-linux-mysql-replay\after-v1.pdf
```

baseline 파일이 없거나 JSON이 잘못되면 현재 JSON은 저장되고 비교만 UNAVAILABLE로 남는다. ERROR/미수집 결과를 개선으로 처리하지 않는다. current와 replay를 서로 전후 baseline으로 연결하면 자산 불일치로 INCOMPARABLE이다.

## 남는 범위와 제한

Linux 5개/MySQL 5개 내부 기준의 실제 설정 개선을 확인했다. SSH 실제 로그인, rsyslog 이벤트 전달·보존, 모든 서비스·계정의 포괄적 감사, TCP TLS handshake/인증서 검증, 재부팅 후 정책 영속성은 이 PASS의 범위가 아니다. MySQL 변경은 현재 GLOBAL 값이고 데이터·인증 파일은 tmpfs다. 기존 보고서·원본 증적을 수정하지 않았으며 commit/push를 수행하지 않았다.
