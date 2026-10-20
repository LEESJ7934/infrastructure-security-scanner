# Day 18~20 최종 검증 및 사용자 실행 절차

## 코드와 실측의 구분

기존 브랜치와 Draft PR #1을 유지합니다. 이 문서는 프로젝트 루트 `infrastructure-security-scanner-lab`의 VS Code PowerShell을 기준으로 합니다. 비밀번호·개인 경로를 Git에 추가하지 않습니다.

- Work: Nuclei 바이너리/버전/템플릿 검증, 안전한 JSONL 출력 및 V7 연결, Docker HTTP/FTP 개선 후 재점검, 독립 SQL 앱 검증, 보고서·테스트 구현.
- GitHub Actions: 일회용 Docker/MySQL에서 실제 Nuclei와 HTTP·FTP 전후 이력, DVWA 읽기 전용 재현, V6→V7 보존, JSON/PDF·해시 확인. 최신 실행의 성공 여부를 확인해야 합니다.
- 사용자 확인 완료: EC2 FTP 익명 인증 230, SSH 비밀번호 인증 비활성, HTTP 보안 헤더 4종 누락, DVWA 정상 1행→우회 5행. DVWA는 사용자 확인 기준 Windows V7 scan 7/port 4 저장·무결성 MATCH.
- 사용자 실행 대기: FTP/HTTP/SSH V7 추가 저장, 신규 로컬 정상 스캔, EC2 대상 Nuclei, 실제 Windows 통합 보고서. Work나 CI가 사용자 DB를 직접 조회한 것은 아닙니다.

운영 SSH, 기존 EC2 FTP/DVWA, AWS 보안 그룹, 기존 데이터, 다크웹 컨테이너는 변경하지 않습니다. t3.micro에 신규 컨테이너를 배포하지 않습니다. 이번 Work에서 병합·브랜치 삭제는 하지 않습니다.

## 1. Windows: 기존 데이터와 브랜치 확인

```powershell
git switch feat/controlled-lab-verification-20261020
git pull --ff-only origin feat/controlled-lab-verification-20261020
py -m scripts.windows_v7_preflight
```

Day 15~17이 미완료라면 [기존 실행 절차](day15_17_work1.md)를 먼저 진행합니다. 새 로컬 scan_id를 임의로 만들거나 기존 ID를 재사용하지 않습니다. 기존 scan 7의 HTTP 포트가 실제로 4인지, 호스트가 어떤 EC2/터널을 가리키는지 대조합니다. 최신 상태 포트 테이블에서 과거 scan 7의 포트가 없어졌다면 새 스캔을 실행해 덮지 말고 결과를 검토합니다.

## 2. Windows: 공식 Nuclei 배포본 준비

설치 대상은 Windows PC입니다. EC2의 CPU/RAM을 사용해 Nuclei를 실행하지 않습니다. 저장 경로는 Git에서 제외된 `evidence/`입니다. 이미 파일이 있으면 새 디렉터리명을 선택합니다.

```powershell
New-Item -ItemType Directory -Force evidence/tools | Out-Null
Invoke-WebRequest -Uri 'https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_windows_amd64.zip' -OutFile evidence/tools/nuclei_windows.zip
py -m scripts.prepare_nuclei --archive evidence/tools/nuclei_windows.zip --platform windows_amd64 --destination evidence/tools/nuclei-3.11.1
```

공식 [v3.11.1 배포 페이지](https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1)의 자산 SHA-256을 코드에 고정했습니다. Windows ZIP 해시는 `bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2`, Linux amd64 ZIP은 `ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6`입니다. ZIP과 추출된 실행 파일은 서로 다른 해시입니다. `prepare_nuclei`가 배포본을 먼저 검사한 뒤 실행 파일 해시를 `nuclei_identity.json`에 기록합니다. 실행기는 그 실행 파일 해시와 `v3.11.1`을 검사하기 전에는 검사를 실행하지 않습니다.

## 3. Windows: 기존 EC2 HTTP에만 SSM 전달

먼저 사전 조회 결과의 scan 7/port 4가 기존 EC2 HTTP 80에 해당함을 확인합니다. 아래 절차는 **DB 대상이 127.0.0.1:80일 때만** 사용합니다. 다른 주소·포트라면 무관한 로컬 서버를 스캔하지 않도록 기존 연결 매핑을 확인해야 합니다. 기존 터널이 있다면 같은 포트에 중복 실행하지 않습니다.

첫 번째 PowerShell에서 로컬 80 포트 점유를 조회합니다.

```powershell
Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
```

다른 서비스가 점유하고 있으면 해당 프로세스를 종료하지 말고 연결 구성을 검토합니다. 비어 있을 때만 다음 SSM 전달을 실행해 창을 유지합니다. AWS CLI와 Session Manager Plugin이 기존 설정돼 있어야 합니다.

```powershell
aws ssm start-session --target i-036b5556c800856e0 --region ap-northeast-2 --document-name AWS-StartPortForwardingSession --parameters 'portNumber=80,localPortNumber=80'
```

이는 기존 인스턴스의 기존 HTTP 80에 대한 임시 세션이며 새 AWS 유료 리소스나 공개 접근 규칙을 만들지 않습니다. 연결이 끝나면 이 창에서 Ctrl+C로 터널만 종료합니다.

### AWS SSM Ubuntu: 필요 시 기존 서비스 조회만

```bash
date -u
ss -ltn | awk 'NR==1 || $4 ~ /:(21|22|23|80)$/'
```

EC2 FTP/HTTP/SSH 원본 수집은 [Day 15~17 절차](day15_17_work1.md)의 `collect_ec2_config_evidence.py`를 그대로 사용합니다. `sshd -T`는 기본 설정 조회이며 Match 블록·실제 데몬의 다른 인수까지 증명하지 않습니다. 여기에서 서비스 재시작·설정 수정·DB 초기화를 실행하지 않습니다.

## 4. 두 번째 Windows PowerShell: Nuclei와 V7 저장

원래 프로젝트 루트에서 실행합니다. 스캔 ID/포트 ID는 기존 DB 조회와 대조한 값이며 아래 7/4를 무조건 신뢰하지 않습니다. Scope 파일에는 현재 검사 시각과 실제 DB 대상 주소의 승인이 필요합니다.

```powershell
$ec2ScanId = 7
$ec2HttpPortId = 4
$scopeFile = Read-Host '현재 EC2/터널 대상이 승인된 Scope 파일'
$identity = Get-Content evidence/tools/nuclei-3.11.1/nuclei_identity.json -Raw | ConvertFrom-Json
$templateHash = (Get-FileHash lab/nuclei/missing-nosniff.yaml -Algorithm SHA256).Hash.ToLower()
$nucleiArgs = @('--scan-id',"$ec2ScanId",'--port-id',"$ec2HttpPortId",'--environment','EC2_LAB','--scope-file',$scopeFile,'--check','NUCLEI','--nuclei-binary','evidence/tools/nuclei-3.11.1/nuclei.exe','--binary-sha256',$identity.binary_sha256,'--nuclei-version',$identity.version,'--template-root','lab/nuclei','--template-name','missing-nosniff.yaml','--template-sha256',$templateHash,'--timeout','60')
py -m scripts.run_lab_special @nucleiArgs --dry-run
py -m scripts.run_lab_special @nucleiArgs --jsonl-output evidence/nuclei_ec2_reviewed.jsonl
```

사용 템플릿은 읽기 전용 GET으로 nosniff 헤더만 확인합니다. 전체 CVE 점검이 아니며 매칭은 POTENTIAL입니다.

원본 Nuclei stdout JSONL 바이트의 SHA-256을 증적에 보존하되 요청/응답 원문은 보관하지 않습니다. 사용자에게 저장하는 JSONL은 검증된 템플릿 ID·심각도·대상 해시만 포함하며 별도 SHA-256을 V7 증적에 연결합니다. 원본 stdout 해시와 정제 JSONL 파일 해시는 다릅니다. JSONL의 다른 대상·포트·템플릿 결과는 거부합니다. 인터랙트 서버·리다이렉트·자동 업데이트 확인을 끄고 동시성 1·초당 1회로 제한합니다. 템플릿 내용이 바뀌면 검토 없이 새 해시를 승인하지 않습니다.

실행 오류는 `ERROR / INCONCLUSIVE`, 보고서 검사 커버리지는 `NOT_TESTED`입니다. 실패 유형은 V7에 저장하며 실패한 결과를 안전 판정으로 바꾸지 않습니다. 저장 실패 자체가 발생하면 DB 기록도 없으므로 완료라고 하지 않습니다.

## 5. Day 19: Docker 재점검과 별도 안전 SQL 앱

최신 GitHub Actions `격리 실습 통합 검증`은 같은 `ftp-weak:2122`와 `http-weak:8082`를 유지하면서 각각 익명 인증 차단·보안 헤더 적용 후 재점검합니다. 변경 범위는 일회용 CI Docker 서비스 두 개뿐입니다. 기존 EC2 21/80에는 이 Compose 명령을 적용하지 않습니다. CI는 조치 전후 V7 행을 보존하고 FTP `CONFIRMED→NOT_DETECTED`, HTTP 및 nosniff Nuclei `POTENTIAL→NOT_DETECTED` 여부를 검사합니다. 최종 결과는 해당 실행의 성공 기록을 근거로 삼습니다.

SQL 비교는 DVWA와 다른 애플리케이션입니다. EC2/DVWA가 수정됐다는 전후 증거로 사용하지 않습니다. Day 15 정상 서버가 계속 실행 중이면 Windows에서 실제 새 로컬 scan_id와 8081 port_id를 사용합니다.

```powershell
$localScanId = [int](Read-Host '실제로 생성된 로컬 정상 scan_id')
$localHttpPortId = [int](Read-Host '그 스캔의 HTTP 8081 실제 port_id')
py -m scripts.verify_safe_sql_baseline --scan-id $localScanId --port-id $localHttpPortId --scope-file config/scope.example.json --output evidence/safe_sql_baseline.json
```

정상 입력 1행, 동일 SQLi 형태 입력 0행, 각 응답 SHA-256과 검사 시각을 보존합니다. 이 별도 앱 증적은 스키마를 바꾸지 않고 파일로 저장해 통합 보고서에 연결합니다. SQLi에 대응하는 새 V7 enum/마이그레이션은 추가하지 않습니다.

## 6. Day 20: 실제 DB 통합 보고서와 확인

```powershell
py -m scripts.generate_integrated_lab_report --local-scan-id $localScanId --ec2-scan-id $ec2ScanId --safe-sql-evidence-file evidence/safe_sql_baseline.json --output-dir reports --format both
```

별도 안전 SQL 앱을 실행하지 않았으면 `--safe-sql-evidence-file`을 생략합니다. 해당 부분은 `NOT_TESTED`로 남습니다. Nuclei와 FTP/HTTP/SSH도 저장된 증적만 반영하며 원본 없는 사용자 진술을 새 DB 행으로 만들지 않습니다. 기존 사용자 저장 DVWA와 새로 저장된 FTP 증적을 보고서에서 확인할 때에만 각 검사 `CONFIRMED`를 표시합니다. 특정 CVE의 확정과 구별합니다.

생성된 JSON에서 모든 증적과 보고서 해시를 확인합니다.

```powershell
$report = Read-Host '생성된 integrated_lab JSON 경로'
py -c "import json,sys; from api.analysis_report import snapshot_sha256; d=json.load(open(sys.argv[1],encoding='utf-8')); assert snapshot_sha256(d)==d['integrity']['snapshot_sha256']; c=d['lab_comparison']; assert all(r['evidence_integrity']=='MATCH' for g in c['environments'].values() for r in g['observations']); print('snapshot/evidence: MATCH'); print(json.dumps({e:g['coverage'] for e,g in c['environments'].items()},indent=2)); print(json.dumps(c['retests'],indent=2)); print(d['independent_sql_baseline']['status'])" $report
```

`retests`는 같은 스캔·자산·포트·환경·검사의 서로 다른 시각 증적만 비교합니다. 해시 불일치·실행 실패·INCONCLUSIVE·다른 서비스·동일 시각은 전후 성공으로 묶지 않습니다. 변화가 관찰됐다는 사실과 어떤 조치를 수행했는지는 구분하고 변경 기록이 있는 경우 함께 출력합니다. `EC2_LAB`은 DB 저장 라벨이며 CI 보고서에는 `GITHUB_ACTIONS_DISPOSABLE_DOCKER` 실행 맥락을 별도로 표시합니다.

## 병합 전 남은 확인

사용자는 일반 Chat에서 새 로컬 ID, 추가 증적 저장 결과, 실제 Nuclei 실행 결과, 최종 JSON/PDF와 해시 검증 출력을 확인해야 합니다. 기존 EC2의 설정 개선은 승인·실행하지 않았으므로 완료로 쓰지 않습니다. 새 실환경 스크린샷이 없다면 만들지 않으며 기존 핵심 화면을 유지합니다. 이 확인이 끝나기 전에는 프로젝트 전체 실환경 검증 완료나 Squash 병합 준비 완료라고 단정하지 않습니다. 최종 병합은 별도 사용자 승인 후 `포트스캐너 보안 검증 기능 및 포트폴리오 개선` 메시지로 수행할 계획이며 이번 Work에서는 실행하지 않습니다.
