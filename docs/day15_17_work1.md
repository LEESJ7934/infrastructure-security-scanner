# Day 15~17 Work 1회차 실행 지침

## 상태와 범위

코드는 기존 브랜치 `feat/controlled-lab-verification-20261020`에만 반영합니다. Draft PR #1을 유지하며 main 병합, Day 18~20, EC2 설정 변경은 범위 밖입니다.

- Day 15: Python 루프백 정상 서버, 실제 HTTP checker의 `NOT_DETECTED` 판정 및 파라미터 SQL 조회를 자동 검증. 사용자 Windows의 신규 스캔/V7 저장은 아래 실행 결과로 확인해야 합니다.
- Day 16: 사용자 실행 전용 EC2 읽기 전용 수집기와 Windows 가져오기 구현. FTP/HTTP/SSH 실제 원본은 이 Work에서 확보하지 않았습니다. 사용자 보고 기준 기존 DVWA는 scan 7 / HTTP port 4에 저장돼 있습니다.
- Day 17: 서로 다른 실제 스캔 ID를 한 읽기 전용 스냅샷으로 집계하는 기존 JSON/PDF 기능 활용. 항목별 증적, 해시, 위험도·권고 및 독립 애플리케이션 비교 문구 보강. 실제 사용자 데이터로 통합 출력은 Windows 실행 대기입니다.

원본 해시는 전달 중 바이트 일치 확인이며 EC2 출처를 인증하는 전자서명이 아닙니다. EC2 내부 127.0.0.1과 Windows 127.0.0.1은 다른 컴퓨터입니다. `--expected-host`는 기존 DB 자산과 EC2/터널의 관계를 사용자가 확인한 뒤 지정합니다. 잘못된 스캔을 연결해서는 안 됩니다.

## 1. VS Code Windows PowerShell — 브랜치 갱신

프로젝트 루트에서 실행합니다. 작업 중인 변경사항 때문에 pull이 실패하면 덮어쓰거나 reset하지 말고 출력을 확인합니다.

```powershell
git switch feat/controlled-lab-verification-20261020
git pull --ff-only origin feat/controlled-lab-verification-20261020
py -m scripts.windows_v7_preflight
```

기존 `.env`를 사용합니다. 마이그레이션 재실행, DB 초기화, 기존 데이터 삭제는 필요하지 않습니다. `current_scan_port_candidates`에서 scan 7의 호스트 및 FTP 21 / SSH 22 / HTTP 80의 **실제 port_id**를 확인합니다. HTTP 기존 port 4도 현재 연결과 대조합니다. 조회 결과에 없으면 새 스캔으로 기존 상태를 덮지 말고 결과를 먼저 검토합니다. 포트 테이블은 최신 상태를 저장하므로 더 최근 스캔이 있다면 과거 scan 7에 임의로 연결하지 않습니다.

## 2. Day 15 — 정상 로컬 실행

첫 번째 PowerShell에서 서버를 실행하고 유지합니다.

```powershell
py -m scripts.run_local_http_baseline
```

두 번째 PowerShell에서:

```powershell
Test-NetConnection 127.0.0.1 -Port 8081 -InformationLevel Quiet
py -c "import requests; s=requests.Session(); s.trust_env=False; u='http://127.0.0.1:8081/lookup'; a=s.get(u,params={'id':'1'},timeout=5); b=s.get(u,params={'id':chr(39)+' OR 1=1 --'},timeout=5); print('normal:',a.status_code,a.text); print('SQL input:',b.status_code,b.text); assert 'First name: Alex' in a.text and b.text=='No results'"
py -m scripts.run_scan scan -sT -sV --target 127.0.0.1 --ports 8081 --scope-file config/scope.example.json --max-workers 1
```

`DB save completed (scan_id=...)`의 **새 ID**를 입력합니다. 기존 9번 또는 예시 ID를 재사용하지 않습니다.

```powershell
$localScanId = [int](Read-Host '방금 생성된 로컬 scan_id')
py -m scripts.run_lab_verification --scan-id $localScanId --environment LOCAL_BASELINE --scope-file config/scope.example.json --dry-run
py -m scripts.run_lab_verification --scan-id $localScanId --environment LOCAL_BASELINE --scope-file config/scope.example.json
py -m scripts.generate_lab_comparison --scan-id $localScanId --json reports/local_v7.json --pdf reports/local_v7.pdf
```

기대 결과는 `LOCAL_BASELINE / HTTP_SECURITY_HEADERS / SUCCESS / NOT_DETECTED`와 `evidence_integrity=MATCH`입니다. 이 결과는 HTTP 헤더 점검에 한정됩니다. SQL 입력 비교는 안전한 별도 SQLite 애플리케이션의 테스트이며 DVWA가 수정됐다는 뜻이 아닙니다.

## 3. Day 16 — 수집기 전달

별도 설치 없이 Python 표준 라이브러리만 사용합니다. Windows에서 현재 체크아웃의 수집기를 Base64로 출력합니다.

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path scripts/collect_ec2_config_evidence.py)))
(Get-FileHash scripts/collect_ec2_config_evidence.py -Algorithm SHA256).Hash.ToLower()
```

### AWS SSM Linux

기존 프로젝트 경로·Git 설치를 가정하지 않습니다. 아래 문자열에 위 Base64 한 줄을 붙여 넣습니다. `xb`로 기존 파일을 덮어쓰지 않습니다. 이미 파일이 있다면 새 출력 파일명을 선택합니다.

```bash
python3 - <<'PY'
import base64, hashlib
raw = base64.b64decode('PASTE_COLLECTOR_BASE64', validate=True)
with open('/tmp/scanner_config_collector.py', 'xb') as f:
    f.write(raw)
print(hashlib.sha256(raw).hexdigest())
PY
```

양쪽 수집기 해시가 같은지 확인합니다. 사용자 소유의 승인된 EC2 세션에서만 아래 명령을 실행합니다. 네트워크 요청은 EC2 내부 127.0.0.1의 기존 서비스로 한정됩니다. FTP는 익명 로그인 1회만 시도하고 파일 조회·쓰기 없이 종료합니다. HTTP는 GET `/`의 보안 헤더 존재/값 적합 여부만 수집하고 본문·세션값은 저장하지 않습니다.

```bash
python3 /tmp/scanner_config_collector.py --check FTP_ANONYMOUS --output /tmp/ec2_ftp.json
python3 /tmp/scanner_config_collector.py --check HTTP_SECURITY_HEADERS --output /tmp/ec2_http.json
python3 /tmp/scanner_config_collector.py --check SSH_AUTH_POLICY --output /tmp/ec2_ssh.json
sha256sum /tmp/ec2_ftp.json /tmp/ec2_http.json /tmp/ec2_ssh.json
base64 -w0 /tmp/ec2_ftp.json; echo
base64 -w0 /tmp/ec2_http.json; echo
base64 -w0 /tmp/ec2_ssh.json; echo
```

SSH는 `sudo -n /usr/sbin/sshd -T` 조회만 실행합니다. 권한 부족 시 `ERROR`로 남기며 설정·권한을 변경하지 않습니다. 기본 설정의 PasswordAuthentication만을 판정하며 실제 데몬의 다른 실행 인수·대체 설정 파일 및 접속 조건별 Match 정책은 별도 검토해야 합니다. 비밀번호 인증이 비활성이라는 결과를 SSH 전체가 안전하다는 의미로 사용하지 않습니다.

### VS Code Windows PowerShell — 원본 저장·가져오기

```powershell
New-Item -ItemType Directory -Force evidence | Out-Null
foreach ($name in @('ftp','http','ssh')) {
    $encoded = Read-Host "$name 원본 Base64 한 줄"
    [IO.File]::WriteAllBytes((Join-Path $PWD "evidence/ec2_$name.json"), [Convert]::FromBase64String($encoded))
    Get-FileHash "evidence/ec2_$name.json" -Algorithm SHA256
}
```

SSM 출력 원본 SHA-256과 일치하는지 확인한 뒤, 아래에서 해당 **SSM 원본 해시**를 입력합니다. 로컬 해시만 새로 계산해 넣으면 원격 원본과의 전달 무결성 확인을 대신할 수 없습니다.

```powershell
$ec2ScanId = 7
$dbHost = Read-Host 'scan 7의 실제 DB host_ip (EC2/터널 관계 확인 후 입력)'
$scope = Read-Host '해당 DB host_ip와 수집 시각을 승인한 scope 파일 경로'
$ftpPortId = [int](Read-Host 'scan 7 FTP 21의 실제 port_id')
$httpPortId = [int](Read-Host 'scan 7 HTTP 80의 실제 port_id (기존 4와 대조)')
$sshPortId = [int](Read-Host 'scan 7 SSH 22의 실제 port_id')
$ports = @{ftp=$ftpPortId; http=$httpPortId; ssh=$sshPortId}
foreach ($name in @('ftp','http','ssh')) {
    $sourceHash = Read-Host "$name SSM 원본 SHA-256"
    $argsForImport = @('--evidence-file',"evidence/ec2_$name.json",'--source-sha256',$sourceHash,'--scope-file',$scope,'--scan-id',"$ec2ScanId",'--port-id',"$($ports[$name])",'--expected-host',$dbHost)
    py -m scripts.import_ec2_config_evidence @argsForImport
    if ($LASTEXITCODE -ne 0) { throw "$name dry-run 실패: 저장 중단" }
    py -m scripts.import_ec2_config_evidence @argsForImport --commit
    if ($LASTEXITCODE -ne 0) { throw "$name 저장 실패: 중단" }
}
py -m scripts.generate_lab_comparison --scan-id $ec2ScanId --json reports/ec2_v7_findings.json --pdf reports/ec2_v7_findings.pdf
```

`--commit` 없는 호출은 DB 조회만 합니다. 동일 원본·스캔·포트·검사 항목은 MySQL 연결 잠금으로 직렬화하고 기존 ID를 반환합니다. 동일 원본을 다른 scope/binding으로 재입력하면 실패하며 기존 행을 수정하지 않습니다. 새로운 수집 시각의 원본은 새 이력으로 보존합니다. 기존 DVWA 증적도 삭제·수정하지 않습니다. 수집 실패는 `ERROR / INCONCLUSIVE`이고 검증 커버리지에서는 `NOT_TESTED`로 남습니다.

## 4. Day 17 — 실제 정상/EC2 데이터 보고서

Day 15의 새 스캔 ID와 기존 EC2 scan 7을 사용합니다. 위 PowerShell 변수가 사라졌다면 실제 ID를 다시 입력합니다.

```powershell
py -m scripts.generate_integrated_lab_report --local-scan-id $localScanId --ec2-scan-id $ec2ScanId --output-dir reports --format both
```

생성된 JSON 경로를 넣어 저장된 증적 해시와 스냅샷 해시를 검증합니다.

```powershell
$reportPath = Read-Host '생성된 integrated_lab JSON 경로'
py -c "import json,sys; from api.analysis_report import snapshot_sha256; d=json.load(open(sys.argv[1],encoding='utf-8')); c=d['lab_comparison']; rows=[r for g in c['environments'].values() for r in g['observations']]; assert d['integrity']['snapshot_sha256']==snapshot_sha256(d); assert rows and all(r['evidence_integrity']=='MATCH' for r in rows); print('snapshot/evidence hashes: MATCH'); print(json.dumps({e:g['coverage'] for e,g in c['environments'].items()},indent=2)); print([(r['check'],r['execution_status'],r['finding_status']) for r in c['environments']['EC2_LAB']['observations']])" $reportPath
```

사용자 실행 후 확인할 결과:

| 환경 | 항목 | 확인 기준 (미실행 결과를 성공으로 가정하지 않음) |
|---|---|---|
| LOCAL_BASELINE | HTTP_SECURITY_HEADERS | SUCCESS / NOT_DETECTED / MATCH |
| EC2_LAB | FTP_ANONYMOUS | 원본 응답이 230이면 SUCCESS / CONFIRMED / MATCH |
| EC2_LAB | HTTP_SECURITY_HEADERS | 원본에서 4종 누락이면 SUCCESS / POTENTIAL / MATCH |
| EC2_LAB | SSH_AUTH_POLICY | 원본의 passwordauthentication=false이면 SUCCESS / NOT_DETECTED / MATCH |
| EC2_LAB | DVWA_SQLI | 기존 사용자 저장 CONFIRMED / MATCH 유지 |
| 미실행 | NUCLEI 등 | NOT_TESTED 유지 (새로 실행하지 않음) |

PDF에서도 검증 시각, 실행/판정 분리, 증적과 SHA-256, scope와 자산, 정성적 위험도와 개선 방향을 표시합니다. 프레임 보호는 X-Frame-Options 또는 CSP frame-ancestors를 인정합니다. 로컬과 EC2는 다른 애플리케이션이며 동일 서비스의 조치 전후를 의미하지 않습니다. 과거 오류도 보존하므로 각 시점의 기록을 확인합니다.

## Work 검증과 남은 작업

- 신규 가져오기 단위 테스트, 로컬 실제 프로세스 HTTP/SQL 테스트, 기존 보고서 테스트, 전체 회귀, 구문, diff, 민감정보 검사를 실행합니다.
- Docker 통합 CI에서는 일회용 MySQL V7의 실제 중복 방지 SQL과 JSON/PDF 생성을 확인합니다. CI의 EC2_LAB은 Docker 모의 환경 라벨이며 AWS 실측이 아닙니다.
- 이 Work에서는 실제 Windows/MySQL에 접근하지 않았습니다. 기존 DVWA 저장은 사용자 확인 완료, Day 15 신규 저장·Day 16 추가 저장·Day 17 실제 데이터 출력은 사용자 실행 대기입니다.
- 공유하는 출력에서 개인 경로·인증값·세션·식별값을 제외합니다. `evidence/`, `.env`, `reports/`를 Git에 추가하지 않습니다.
