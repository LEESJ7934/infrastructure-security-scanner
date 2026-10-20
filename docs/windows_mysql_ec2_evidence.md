# Windows MySQL에 실제 EC2 DVWA 증적 저장

이 문서는 **사용자 소유 EC2에 접속한 SSM 웹 터미널**과 **Windows PowerShell의 로컬 스캐너/MySQL**을 구별합니다. 두 시스템의 `127.0.0.1`은 **서로 다른 장비**입니다. 기존 데이터·CVE 상태를 덮어쓰지 않습니다.

## 1. Windows PowerShell — 기존 DB 읽기 전용 확인

```powershell
cd <PROJECT_DIRECTORY>
git switch feat/controlled-lab-verification-20261020
git pull --ff-only
py -m pip install -r requirements.txt
py -m scripts.windows_v7_preflight
```

`.env`의 기존 `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` 값으로 연결합니다. DB 암호 또는 `.env` 전체를 채팅/노션에 보내지 않습니다.

- `required_v6_tables_present`: 참이어야 합니다.
- `v7_table_present`과 `v7_schema_complete`: 참이면 마이그레이션을 재실행하지 않습니다.
- `current_http_scan_port_candidates`에 나오는 기존 행은 **그 자체만으로 EC2 증적이 아닙니다**. 사용자 PC의 로컬 `127.0.0.1`과 SSM 터널 `127.0.0.1`의 출처는 명시적으로 구분해야 합니다.
- MySQL 연결에 실패하면 추가 설치나 초기화를 하기 전에 기존 `.env`와 DB 실행 방식부터 확인합니다.

### V7이 아직 없다면

**백업이 성공한 후에만** V7 DDL을 적용합니다. MySQL이 프로젝트 Docker Desktop의 `portscan-mysql` 컨테이너에 있는 경우, PowerShell에서 기존 볼륨을 유지한 채 다음처럼 덤프합니다.

```powershell
New-Item -ItemType Directory -Force .\backup | Out-Null
docker exec portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump -uroot --single-transaction --routines --triggers --events --databases port_scan --result-file=/tmp/port_scan_before_v7.sql'
docker cp portscan-mysql:/tmp/port_scan_before_v7.sql .\backup\port_scan_before_v7.sql
Get-Item .\backup\port_scan_before_v7.sql | Select-Object Name,Length
Get-FileHash -Algorithm SHA256 .\backup\port_scan_before_v7.sql
```

덤프 실패 또는 0바이트 파일이면 **여기서 중단**합니다. 이 백업은 호스트 파일을 직접 만드는 형태라 PowerShell 5.1의 파이프/리디렉션 인코딩 문제를 피합니다. 필요하면 외부 안전한 백업 장소에도 별도 보관합니다.

성공적으로 백업한 뒤에만 (Docker MySQL인 경우):

```powershell
Get-Content -Raw -Encoding UTF8 .\sql\migration_v7.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot --default-character-set=utf8mb4'
if ($LASTEXITCODE -ne 0) { throw "V7 migration failed" }
py -m scripts.windows_v7_preflight
```

MySQL이 **Windows 네이티브 서비스**라면 Docker 명령을 실행하지 마세요. 기존 MySQL 클라이언트의 인증/백업 방법을 확인한 후 같은 V7 마이그레이션을 적용합니다.

## 2. EC2 SSM 브라우저 — 원본 JSON을 Windows로 이동

실제 사용자 EC2의 원본은 `/tmp/dvwa_sqli_evidence.json`이고, 정상 1행·비파괴 SQLi 5행을 확인했습니다. EC2 터미널에서 **데이터를 변경하지 않는** 명령:

```bash
sha256sum /tmp/dvwa_sqli_evidence.json
base64 -w0 /tmp/dvwa_sqli_evidence.json; printf '\n'
```

출력된 Base64 한 줄은 **사용자 Windows PC로만** 복사하세요. Base64는 암호화가 아닙니다. 인증정보가 없더라도 증적은 공개 GitHub/노션/채팅으로 복사하지 않습니다.

Windows PowerShell(로컬 프로젝트 루트):

```powershell
New-Item -ItemType Directory -Force .\evidence | Out-Null
$b64 = Read-Host "Paste the one-line EC2 evidence Base64"
[IO.File]::WriteAllBytes((Join-Path (Get-Location) 'evidence\dvwa_sqli_evidence.json'),[Convert]::FromBase64String($b64.Trim()))
Remove-Variable b64
Get-FileHash -Algorithm SHA256 .\evidence\dvwa_sqli_evidence.json
```

Windows에서 계산한 해시가 EC2 `sha256sum` 출력과 **완전히 일치**해야 합니다. 다르면 중단하세요. `evidence/` 폴더는 `.gitignore`에 등록했습니다.

## 3. 실제 EC2 자산·포트와 결합한 뒤 V7 저장

우선 `py -m scripts.windows_v7_preflight`에 나온 스캔 ID·포트 ID의 출처를 확인합니다. 현재 EC2의 DVWA는 **포트 80**이며, CI Docker 실습의 포트 4280과 다릅니다. Windows 스캐너가 SSM 포트 전달로 EC2의 80을 명시적으로 스캔했다면 **Windows의 로컬 포트 번호**가 포트 테이블에 저장됩니다. 이를 실제 EC2 이력으로 표시하려면 해당 스캔 실행과 터널의 대응 관계가 별도 증적으로 존재해야 합니다.

DB에 EC2 HTTP 실측 스캔이 **없는 경우** 단순히 Windows에서 발견된 다른 HTTP 포트에 연결하거나 임의 ID/행을 만들어서는 안 됩니다. 먼저 승인된 SSM 세션을 통한 EC2 실제 HTTP 포트 스캔을 새로 기록합니다.

기존 실제 스캔의 `scan_id`, `port_id`, 허용 범위 `scope_file`이 확보되면, 먼저 **쓰기 없는 dry-run**:

```powershell
py -m scripts.import_ec2_dvwa_evidence --evidence-file .\evidence\dvwa_sqli_evidence.json --scope-file .\config\scope.example.json --scan-id <ACTUAL_EC2_SCAN_ID> --port-id <ACTUAL_EC2_HTTP_PORT_ID>
```

검증 출력의 `status=DRY_RUN`, `writes_performed=false`, `finding_status=CONFIRMED`를 확인하고, EC2 원본 해시와 `source_file_sha256`을 비교합니다. 사용자 소유 승인 범위 및 진짜 SSM 스캔과의 대응을 재확인한 뒤에만 **명시적 저장**:

```powershell
py -m scripts.import_ec2_dvwa_evidence --evidence-file .\evidence\dvwa_sqli_evidence.json --scope-file .\config\scope.example.json --scan-id <ACTUAL_EC2_SCAN_ID> --port-id <ACTUAL_EC2_HTTP_PORT_ID> --commit
```

`status=RECORDED`, `observation_id`, `evidence_sha256`이 나오는지 확인합니다. DB에는 원본 파일 해시와 정규화된 증적 해시가 **서로 다른 목적**으로 저장됩니다. 이 절차는 실제 EC2의 독립적인 암호학적 증명을 제공하지 않습니다.

## 4. 최종 보고서

정상 로컬 스캔과 EC2 실습 스캔 **각각의 실제 ID**가 있을 때만:

```powershell
py -m scripts.generate_integrated_lab_report --local-scan-id <LOCAL_SCAN_ID> --ec2-scan-id <EC2_SCAN_ID> --output-dir reports --format both
```

보고서와 증적의 상태 및 해시를 검증한 후에만 포트폴리오 결과를 'V7 실제 저장 완료'로 수정합니다. 현재 이 문서와 저장소에서는 **실제 Windows DB 기록을 직접 수행한 적이 없습니다**.
