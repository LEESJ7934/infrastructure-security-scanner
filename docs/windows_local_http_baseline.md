# Windows 로컬 정상 HTTP 실습 환경 비교 (EC2 DVWA 수동 검증 이후)

**관찰된 실제 상태(사용자 PowerShell 출력):** 기존 127.0.0.1:8081 연결은 실패했고, 현재 Docker에서는 `portscan-mysql`, darkweb-monstache/kibana/elasticsearch 등이 실행 중이었습니다. 기존 MySQL 스캔 ID 9의 8081 기록은 **과거 기록**으로 현재 정상 여부를 증명하지 않습니다. 별도 실행 중인 darkweb `monstache` 재시작 문제는 이 작업에서 건드리지 않습니다.

## 1. 첫 번째 PowerShell: 정상 로컬 HTTP 서버 시작

```powershell
cd "C:\Users\Seung Jun\Desktop\Semi-Project\infrastructure-security-scanner-lab"
git pull --ff-only
py -m scripts.run_local_http_baseline
```

이 프로세스를 **실행된 상태로 유지**합니다. 기존 lab/server.py에서 안전 모드 `LAB_VULNERABLE=0`를 실행하며, Windows 루프백 주소 `127.0.0.1:8081`에만 서버를 띄웁니다. 기존 Docker/AWS/MySQL 리소스와 독립적이고, 세 개의 HTTP 헤더(X-Content-Type-Options, Referrer-Policy, CSP frame-ancestors)를 적용합니다. HTTPS/HSTS 여부는 이 HTTP 실습 범위 밖입니다. SQL 조회는 SQLite 파라미터 바인딩을 사용합니다. 정지할 때는 첫 번째 창에서 Ctrl+C.

## 2. 두 번째 PowerShell: 연결 확인과 실제 스캔 저장

```powershell
cd "C:\Users\Seung Jun\Desktop\Semi-Project\infrastructure-security-scanner-lab"
Test-NetConnection 127.0.0.1 -Port 8081 -InformationLevel Quiet
py -c "import requests; r=requests.get('http://127.0.0.1:8081/',timeout=5); print('HTTP:',r.status_code); print('CSP:',r.headers.get('Content-Security-Policy')); print('XCTO:',r.headers.get('X-Content-Type-Options')); print('Referrer:',r.headers.get('Referrer-Policy'))"
py -m scripts.run_scan scan -sT -sV --target 127.0.0.1 --ports 8081 --scope-file config/scope.example.json --max-workers 1
```

`Test-NetConnection`에서 `True`, 스캔 출력에서 `DB save completed (scan_id=...)`를 확인합니다. **실제 생성된 ID를 사용하며 기존 9번 스캔을 임의로 사용하지 않습니다**. 기존 데이터는 보존하고 새로운 스캔 기록을 추가합니다.

## 3. 추가된 신규 스캔에 대해서만 V7 보안 헤더 검증

```powershell
py -m scripts.run_lab_verification --scan-id <NEW_LOCAL_SCAN_ID> --environment LOCAL_BASELINE --scope-file config/scope.example.json --dry-run
py -m scripts.run_lab_verification --scan-id <NEW_LOCAL_SCAN_ID> --environment LOCAL_BASELINE --scope-file config/scope.example.json
```

`HTTP_SECURITY_HEADERS / SUCCESS / NOT_DETECTED`면 **이 HTTP 헤더 체크에서 누락을 발견하지 못했다**는 뜻입니다. 전반적인 취약점 부재 또는 DVWA SQLi에 대한 로컬 동일 대상 검증을 의미하지 않습니다. SQL 쿼리 방어는 `/lookup?id=1`의 정상 조회와 SQL 메타문자 포함 입력의 반환값 차이로 **별도 비파괴** 확인합니다. CI에서도 HTTP header 및 parameterized SQL 테스트를 실행합니다.

## 4. 실제 데이터로 두 환경의 JSON/PDF 통합 보고서 생성

```powershell
py -m scripts.generate_integrated_lab_report --local-scan-id <NEW_LOCAL_SCAN_ID> --ec2-scan-id 7 --output-dir reports --format both
```

비교 보고서는 정상 실습 HTTP 헤더 결과와 EC2 DVWA SQLi 결과를 **각기 실제 관찰된 범위**에서 나란히 표시합니다. **EC2 쪽 HTTP 헤더/FTP/SSH는 실측되었지만 아직 전부 V7 이력으로 연결되지 않았으므로 보고서에서는 NOT_TESTED가 나타날 수 있습니다**. 이 문구를 정상 판정으로 바꾸지 않습니다. 로컬 테스트의 `127.0.0.1`과 EC2 원격 `127.0.0.1`을 같은 자산으로 해석하지 않습니다.
