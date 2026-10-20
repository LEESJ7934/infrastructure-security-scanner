# 포트폴리오 실제 화면 촬영 가이드

기준: main `51aae3a` / 2026-10-21. **사용자가 Windows VS Code PowerShell에서 직접 수행**합니다. 이 문서는 실행 성공이나 새 이미지 확보를 의미하지 않습니다. 일반 Chat에 이 문서와 마스킹한 실제 출력을 제공하고 한 단계씩 확인합니다.

## 1. 기존 8장 판정 — 원본 이미지 직접 검토

| 번호 | 기존 화면 | 판정 | 실제 화면과 처리 |
|---|---|---|---|
| 1 | 승인 Scope·서비스 식별 | 유지 | 127.0.0.1:8081, Apache 2.4.50, scan 9. 2026-09-15 후속 로컬 실습 기록. 실제 Apache 설치·CVE를 확정하지 않음 |
| 2 | CVE 후보 분석 | 유지 | PREVIEW / CANDIDATE / CVE-2021-42013. DB 저장 완료 화면은 아님 |
| 3 | Read-only CVE 검증 | 설명 수정 | 실제 `result=ERROR`, HTTP 상태 비어 있음. 실패 시 안전 판정하지 않은 사례로 보존. POTENTIAL 성공 캡션 삭제 |
| 4 | 위험도·우선순위 | 유지 | PREVIEW / POTENTIAL / P2 / VERIFY. EPSS는 당시 조회값이며 현재값·실제 자산 침해확률이 아님 |
| 5 | 보고서 요약 | 교체 대기 | 화면에 V6-capable DB snapshot 명시. 과거 V6 예시로 보존하고 새 V7 통합 결과 수령 후 대표 화면 교체 |
| 6 | CVE 상세 | 설명 수정·공개용 교체 대기 | POTENTIAL/P2/VERIFY는 일치. UUID가 실제로 보이므로 기존 “마스킹 완료” 주장은 제거. UUID를 가린 별도 공개본 필요 |
| 7 | 검증 증적 | 유지 | 후보 BANNER와 HTTP_RESPONSE/POTENTIAL 증적이 구분됨. 3번 ERROR와 다른 실행 이력이며 같은 실행 성공으로 묶지 않음 |
| 8 | AWS SG 점검 | 설명 수정 | Provider/Region/Resources와 read-only DRY-RUN만 보임. AWS inventory 예시로 명명. SG 위험 규칙이 검출됐다는 증거 아님 |

기존 이미지는 새 이미지 수령 전 삭제하지 않습니다. 최종 대표 화면은 7개로 제한하고 3·6·7·8번은 상세 근거 영역에 보존합니다. 마스킹 전 원본은 공개 저장소에 추가하지 않습니다.

## 2. 공통 준비와 중단 조건

프로젝트 루트에서 시작합니다. `git status`에 사용자 변경이 있으면 덮어쓰지 말고 먼저 일반 Chat에서 확인합니다.

```powershell
git status --short
git fetch origin
git switch main
git pull --ff-only origin main
git rev-parse HEAD
$py = if (Test-Path .\.venv\Scripts\python.exe) { '.\.venv\Scripts\python.exe' } else { 'python' }
& $py --version
& $py -m scripts.windows_v7_preflight
if ($LASTEXITCODE -ne 0) { throw 'DB 사전 확인 실패: 초기화하지 말고 출력 확인' }
```

- `.env`의 기존 연결을 사용합니다. 암호·환경변수 전체를 출력하지 않습니다.
- `v7_table_present=true`, `v7_schema_complete=true` 확인. false이면 [백업과 V7 준비](windows_mysql_ec2_evidence.md)를 먼저 확인합니다. DB를 새로 만들거나 기존 볼륨을 삭제하지 않습니다.
- 사전 출력의 IP·asset_uid·original_scan_target·개인 경로는 공유 전에 가립니다. 결과 ID만 보고 EC2 출처를 추정하지 않습니다.
- `scan 7 / port 4 / scan 9`는 과거 기록입니다. 아래는 모두 사용자가 현재 DB에서 대조한 값을 입력합니다.
- 실제 네트워크 검사에는 사용자가 소유·승인한 대상과 유효한 Scope가 필요합니다. 오류·해시 불일치·대상 불일치에서는 중단하고 실제 출력을 확인합니다.

```powershell
$ec2ScanId = [int](Read-Host '원본과 대조한 EC2 scan_id')
$scopeFile = Read-Host '현재 승인 범위 파일 경로'
New-Item -ItemType Directory -Force .\reports\portfolio | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$comparisonPath = ".\reports\portfolio\ec2-v7-$stamp.json"
& $py -m scripts.generate_lab_comparison --scan-id $ec2ScanId --json $comparisonPath
if ($LASTEXITCODE -ne 0) { throw 'V7 조회 실패' }
$comparison = Get-Content -LiteralPath $comparisonPath -Raw -Encoding UTF8 | ConvertFrom-Json
$observations = @($comparison.environments.EC2_LAB.observations)
```

이 명령은 기존 DB를 읽어 로컬 JSON을 만들며 대상에 접속하거나 DB를 변경하지 않습니다. 관찰 0건은 미검증이며 성공으로 꾸미지 않습니다.

## 3. 대표 화면 7개 — 위치·캡션·촬영 기준

| 우선 | 이름·기능 | 증명하는 판단 | 처리·PNG | README 위치 / 노션 위치·캡션 |
|---|---|---|---|---|
| 기존 | 승인 Scope·식별 | 승인 대상과 관찰값 연결 | 유지 / `01-scope-service.png` | 대표 화면 1 / 핵심 근거 첫 화면. “승인된 로컬 실습에서 서비스 배너를 식별한 후속 검증 기록” |
| 기존 | CVE 후보 | 버전 일치와 확정 분리 | 유지 / `02-cve-candidate.png` | 대표 화면 2 / 후보 판단. “CVE-2021-42013을 CANDIDATE로 제시한 미리보기” |
| 기존 | 우선순위 | 높은 CVSS·EPSS·KEV에도 VERIFY | 유지 / `03-risk-verify.png` | 대표 화면 3 / 기술 판단. “당시 지표와 자산 맥락으로 P2·VERIFY를 산정” |
| 1 | DVWA 행 확대 | 정상/우회 입력과 확인 범위 | 추가 / `04-dvwa-readonly.png` | 대표 화면 4 / 실측 근거. “해당 DVWA 실습의 조회 행 확대를 재현. 특정 CVE 확정·조치 완료와 구분” |
| 2 | V7 상태·해시 | 저장 상태와 검사 누락을 구별 | 추가 / `05-v7-integrity.png` | 대표 화면 5 / 증적 관리. “저장된 실행·판정·시각·무결성 확인. 미실행은 NOT_TESTED” |
| 3 | Docker FTP·HTTP 재점검 | 같은 서비스에서 조치 후 변화 | 추가 / `06-docker-retest.png` | 대표 화면 6 / 개선 후 재점검. “GitHub Actions 일회용 Docker의 동일 검사 전후. AWS 결과 아님” |
| 4 | 최종 JSON/PDF | 환경·판정·근거·권고 보고 | 5번 교체 / `07-integrated-report.png` | 대표 화면 7 / 최종 결과. “서로 다른 두 환경을 하나의 읽기 전용 스냅샷에서 집계. 비교는 동일 앱 개선 전후가 아님” |

기존 세 장은 재실행 명령이 필요하지 않습니다. 기존 원본 PNG를 제공하면 공개용 식별정보 확인 후 GitHub에도 삽입합니다. 현재 이미지를 새 실행 결과로 날짜 변경하지 않습니다.

### 촬영 1 — DVWA (우선 기존 증적 재사용)

환경: 기존 MySQL V7와 EC2 실측 DVWA 증적. 공통 준비 후:

```powershell
$dvwaRows = @($observations | Where-Object { $_.check -eq 'DVWA_SQLI' })
if ($dvwaRows.Count -eq 0) { throw 'DVWA 증적 없음: 실제 원본 확인 필요' }
$dvwaRows | Select-Object check,execution_status,finding_status,observed_at,evidence_integrity | Format-Table -AutoSize
$dvwaRows | ForEach-Object { $_.evidence.details | ConvertTo-Json -Depth 12 }
```

기대 형태: 성공 증적이면 `SUCCESS / CONFIRMED / MATCH`, details에 정상 입력·우회 입력의 단계와 반환 행 수. **1행→5행은 기존 사용자 기록이며 새 출력이 다르면 새 값을 그대로 검토**합니다. details는 로컬에서만 우선 확인하고 URL·IP·UUID·세션/쿠키·개인 경로가 있는 부분은 공개 캡처에서 제외합니다. 캡처는 검사명, 단계별 입력·행 수, 시각·판정이 보이는 영역으로 한정합니다.

기존 원본 화면에 정상/우회 입력이 충분히 보이면 새 SQLi 요청은 필요 없습니다. 증적에 단계별 내용이 없으면 해당 화면을 완료 처리하지 말고 실제 DVWA 정상·우회 결과 두 화면을 일반 Chat에 요청합니다. DB에서 값을 만들어 넣지 않습니다.

### 촬영 2 — MySQL V7 증적·무결성

환경: 기존 MySQL 8.0 스키마 V7. 공통 준비 후 아래는 읽기 전용 조회 결과만 표시합니다.

```powershell
$observations | Select-Object check,execution_status,finding_status,observed_at,evidence_integrity | Format-Table -AutoSize
$comparison.environments.EC2_LAB.coverage | Format-List
$observations | Select-Object check,evidence_sha256,evidence_integrity | Format-List
```

기대 형태: 실제 저장된 항목별 판정, 증적 SHA-256, `MATCH/MISMATCH`, 누락 검사의 `NOT_TESTED`. **FTP/SSH/HTTP가 없으면 먼저 아래 추가 저장 절차가 필요하며 DVWA만 있어도 그대로 표시**합니다. 캡처는 상태 표와 해시 1~2건, 누락 표시가 함께 보이는 범위입니다. 조회 ID·개인 경로·UUID는 가리고 검사명·시각·상태·해시는 보존합니다.

`MATCH`는 보고서 작성 시 정규화된 DB 증적을 다시 해싱하고 결합 정보를 대조한 결과입니다. 원격 출처 인증이나 원본 파일 전체의 같은 해시는 아닙니다.

### 촬영 3 — 실제 CI 아티팩트의 Docker 재점검

환경: GitHub CLI `gh`와 해당 저장소 접근 권한. 일회용 CI를 Windows에서 재현하거나 기존 DB에 CI fixture를 입력하지 않습니다.

```powershell
$repo = 'LEESJ7934/infrastructure-security-scanner'
$runId = 39453811884
gh run view $runId --repo $repo --json headSha,conclusion,status,url
$ciDir = ".\reports\portfolio\ci-$runId-$stamp"
gh run download $runId --repo $repo --name local-docker-lab-evidence --dir $ciDir
if ($LASTEXITCODE -ne 0) { throw '아티팩트 없음 또는 접근 실패: 새 증적을 만들지 말고 확인' }
Get-ChildItem $ciDir -Recurse -Filter '*.json' | Select-Object Name
$ciJson = Read-Host '다운로드된 실제 integrated_lab JSON 파일 경로'
$ciReport = Get-Content -LiteralPath $ciJson -Raw -Encoding UTF8 | ConvertFrom-Json
$ciReport.runtime_context
$ciReport.lab_comparison.retests | Select-Object check,before,after,change_record,assessment | ConvertTo-Json -Depth 10
Start-Process 'https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39453811884'
```

기대 형태: run `success`, commit `de6b263...`, `GITHUB_ACTIONS_DISPOSABLE_DOCKER`, FTP `CONFIRMED→NOT_DETECTED`, HTTP/NUCLEI `POTENTIAL→NOT_DETECTED`. 실제 결과에 없으면 완료 주장하지 않습니다. 캡처에는 환경 표시·검사명·전후 시각·상태·변경 맥락을 포함합니다. CI 내부 식별자·개인 다운로드 경로는 가립니다. Actions 녹색 배지만으로 재점검 결과를 대체하지 않습니다.

아티팩트 보존기간은 워크플로 기준 7일입니다. 만료되면 일반 Chat에서 원래 보관한 아티팩트 유무를 확인하고, 없다면 현재 커밋의 새 격리 CI 실행을 별도 확인합니다. 과거 실행의 증적을 생성해 대체하지 않습니다. `gh`가 없으면 위 Actions URL의 Artifacts에서 직접 다운로드합니다.

### 촬영 4 — Windows 최종 JSON/PDF

환경: 실제로 저장된 서로 다른 로컬 정상 scan과 EC2 scan, 기존 DB V7. 로컬 정상 스캔이 없다면 다음 절차를 먼저 완료합니다.

첫 번째 PowerShell에서 기존 다른 서비스가 8081을 점유하지 않는지 확인합니다. 점유 중이면 종료시키지 말고 원인을 확인합니다.

```powershell
Get-NetTCPConnection -LocalPort 8081 -State Listen -ErrorAction SilentlyContinue
& $py -m scripts.run_local_http_baseline
```

서버 창을 유지하고 두 번째 프로젝트 루트 PowerShell에서 `$py`, `$scopeFile`을 다시 설정한 뒤:

```powershell
$py = if (Test-Path .\.venv\Scripts\python.exe) { '.\.venv\Scripts\python.exe' } else { 'python' }
$scopeFile = Read-Host '127.0.0.1 실습이 승인된 Scope 파일'
& $py -m scripts.run_scan scan -sT -sV --target 127.0.0.1 --ports 8081 --scope-file $scopeFile --max-workers 1 --dry-run
if ($LASTEXITCODE -ne 0) { throw 'Scope 확인 실패' }
& $py -m scripts.run_scan scan -sT -sV --target 127.0.0.1 --ports 8081 --scope-file $scopeFile --max-workers 1
if ($LASTEXITCODE -ne 0) { throw '스캔 실패' }
$localScanId = [int](Read-Host '방금 실제 출력된 신규 scan_id')
& $py -m scripts.run_lab_verification --scan-id $localScanId --environment LOCAL_BASELINE --scope-file $scopeFile --dry-run
if ($LASTEXITCODE -ne 0) { throw '검증 사전 확인 실패' }
& $py -m scripts.run_lab_verification --scan-id $localScanId --environment LOCAL_BASELINE --scope-file $scopeFile
if ($LASTEXITCODE -ne 0) { throw '실제 검사 실패' }
$ec2ScanId = [int](Read-Host '출처를 대조한 기존 EC2 scan_id')
& $py -m scripts.generate_integrated_lab_report --local-scan-id $localScanId --ec2-scan-id $ec2ScanId --output-dir .\reports\portfolio --format both
if ($LASTEXITCODE -ne 0) { throw '보고서 생성 실패' }
$reportPath = Read-Host '실제 생성된 integrated_lab JSON 경로'
& $py -c "import json,sys; from api.analysis_report import snapshot_sha256; d=json.load(open(sys.argv[1],encoding='utf-8')); assert snapshot_sha256(d)==d['integrity']['snapshot_sha256']; rows=[r for g in d['lab_comparison']['environments'].values() for r in g['observations']]; assert rows, 'No observations'; assert all(r['evidence_integrity']=='MATCH' for r in rows); print('snapshot/evidence: MATCH'); print(d['runtime_context']); print(json.dumps({e:g['coverage'] for e,g in d['lab_comparison']['environments'].items()},indent=2))" $reportPath
$pdfPath = Read-Host '같은 생성 결과의 PDF 경로'
Start-Process -FilePath $pdfPath
```

기대 형태: 로컬 HTTP 검사의 `NOT_DETECTED`, EC2는 저장된 실제 결과만 포함, 미검사는 `NOT_TESTED`, JSON/PDF 경로와 snapshot 해시. PDF에서 실습 비교·재점검·검사 한계가 보이는 페이지를 캡처합니다. 첫 장의 CVE 요약만으로 V7 전체 결과를 대표하지 않습니다. 실제 IP·UUID·경로·계정번호·토큰을 가립니다. 명령 프롬프트 경로는 캡처에서 제외합니다. 운영 EC2 개선 전후라고 캡션을 달지 않습니다.

## 4. 필요한 경우에만: EC2 FTP·SSH·HTTP 원본 수집과 V7 저장

현재 원본이 있으면 재수집하지 말고 원본 해시와 기존 대상 매핑부터 확인합니다. 새 수집은 **사용자 소유 EC2의 SSM Ubuntu 터미널**에서 실행합니다. 아래 Python 수집기를 Windows에서 실행하면 Windows 루프백을 검사하므로 EC2 증적이 되지 않습니다.

Windows PowerShell에서 기존 main의 수집기 내용을 열어 EC2의 새 임시 파일에 그대로 복사합니다. 개인정보·설정값은 포함하지 않습니다.

```powershell
Get-Content .\scripts\collect_ec2_config_evidence.py -Raw
```

EC2 SSM 터미널에서 파일을 준비한 뒤(서비스 설정 변경 없음):

```bash
python3 /tmp/collect_ec2_config_evidence.py --check FTP_ANONYMOUS --output /tmp/ftp_capture.json
python3 /tmp/collect_ec2_config_evidence.py --check SSH_AUTH_POLICY --output /tmp/ssh_capture.json
python3 /tmp/collect_ec2_config_evidence.py --check HTTP_SECURITY_HEADERS --output /tmp/http_capture.json
sha256sum /tmp/ftp_capture.json /tmp/ssh_capture.json /tmp/http_capture.json
```

이미 파일이 있으면 수집기가 덮어쓰지 않고 실패합니다. 이전 원본을 지우지 말고 새 이름을 사용합니다. 필요한 파일 하나씩 `base64 -w0 /tmp/ftp_capture.json`으로 로컬 전달합니다. Base64는 암호화가 아니며 공개 채팅·GitHub에 올리지 않습니다.

Windows에서 원본 바이트를 새 파일로 저장하고 EC2 측 해시와 대조합니다.

```powershell
New-Item -ItemType Directory -Force .\evidence | Out-Null
$evidenceFile = Read-Host '새 로컬 evidence JSON 경로'
if (Test-Path $evidenceFile) { throw '기존 원본 덮어쓰기 금지' }
$b64 = Read-Host 'EC2 원본 Base64 한 줄: 공개 공유 금지'
[IO.File]::WriteAllBytes([IO.Path]::GetFullPath($evidenceFile), [Convert]::FromBase64String($b64.Trim()))
Remove-Variable b64
$sourceHash = (Read-Host 'EC2에서 계산한 원본 SHA-256').Trim().ToLower()
if ((Get-FileHash $evidenceFile -Algorithm SHA256).Hash.ToLower() -ne $sourceHash) { throw '원본 해시 불일치' }
$ec2ScanId = [int](Read-Host '실측 출처와 대조한 기존 scan_id')
$portId = [int](Read-Host '해당 검사 서비스의 기존 port_id')
$expectedHost = Read-Host 'EC2 또는 검증된 터널에 대응하는 DB host IP'
$scopeFile = Read-Host '현재 시각과 원본 검사 시각에 유효한 승인 Scope 경로'
$importArgs = @('--evidence-file',$evidenceFile,'--source-sha256',$sourceHash,'--scope-file',$scopeFile,'--scan-id',"$ec2ScanId",'--port-id',"$portId",'--expected-host',$expectedHost)
& $py -m scripts.import_ec2_config_evidence @importArgs
```

기대 형태는 `DRY_RUN`, `writes_performed=false`. 대상·해시·시각·판정 출력 확인 후에만 다음을 실행합니다.

```powershell
& $py -m scripts.import_ec2_config_evidence @importArgs --commit
if ($LASTEXITCODE -ne 0) { throw '증적 저장 실패' }
```

성공은 `RECORDED_OR_EXISTING`, observation_id와 해시입니다. FTP 230은 익명 인증 허용 `CONFIRMED`, SSH passwordauthentication=false는 기본 비밀번호 정책 `NOT_DETECTED`, 헤더 누락은 `POTENTIAL`입니다. 실제 출력이 다르면 그 값을 사용합니다. 이 importer는 DB 포트 번호 **FTP 21 / SSH 22 / HTTP 80** 및 서비스를 정확히 대조합니다. 다른 로컬 전달 포트에 억지로 연결할 수 없으며, 불일치 시 ID·원본을 변경해서 통과시키지 않습니다. 기존 실측 매핑을 일반 Chat에서 확인합니다.

그 뒤 공통 V7 보고서를 새 파일명으로 다시 생성하고 촬영 2를 진행합니다. SSH Match 조건·실행 중 데몬 인수는 별도 확인 대상입니다.

## 5. Nuclei 화면은 선택 사항

대표 7개 화면에 CI 재점검의 NUCLEI 결과가 있으므로 별도 이미지가 필수는 아닙니다. EC2 실측까지 표시하려면 [Day 18~20의 Nuclei 준비·실행](day18_20_final.md)을 따라 Windows에서 공식 v3.11.1 ZIP, 실행 파일, 버전, 검토한 missing-nosniff 템플릿을 확인해야 합니다. 실제 DB 대상과 SSM 터널 매핑을 확인하기 전에는 명령을 실행하지 않습니다. `POTENTIAL`은 nosniff 누락 가능성이지 CVE 확정이 아닙니다.

## 6. 이미지 제출과 3차 반영

- 원본은 별도 비공개 보관하고 PNG 공개본만 제출합니다. 원본 해시와 공개 이미지 해시는 서로 다릅니다.
- 공개본은 단색 불투명 마스킹으로 IP·계정번호·UUID·호스트명·토큰·암호·개인 경로를 가립니다. 검사 결과·시각·숫자·상태를 바꾸지 않습니다.
- 기존 6번 UUID 마스킹본을 추가 제출합니다. 원본에 대한 “마스킹 완료” 캡션은 이미 정확한 상태로 수정합니다.
- 신규 4장과 기존 대표 3장의 실제 PNG를 받은 뒤 README의 대표 화면 표 아래에 삽입하고, 노션의 대응 위치에 배치합니다. 기존 5번 V6 이미지는 상세 이력으로 이동합니다.
- 다크웹은 현재 Excel·Audit Review·Django 이미지와 문서가 충분하므로 새 실행·촬영을 필수로 요구하지 않습니다. 기존 PNG 전달만으로 GitHub 대표 화면을 추가할 수 있습니다.

일반 Chat 전달용 요청:

> 이 촬영 가이드와 저장소 main을 기준으로 한 번에 한 단계씩 안내해 줘. 먼저 기존 DB와 실측 원본을 읽기 전용으로 확인하고 실제 출력이 맞을 때 다음 단계로 진행해 줘. scan/port ID를 추측하지 말고, EC2·Windows·Docker CI를 구분해 줘. 운영 서비스·기존 DB·다크웹 컨테이너를 변경하지 말고, 새 PNG 4장과 기존 6번 UUID 마스킹본을 준비하도록 도와줘.
