# DVWA 웹 취약점 최종 재점검

2026-11-16 KST에 DVWA `068d974`의 인증된 Security Level **Low**에서 세 경로를 재검증했다. 최종 JSON·PDF와 `evidence/`는 생성한 로컬 작업 사본의 `reports/dvwa-web-final/`에 있다. 이 디렉터리는 Git 제외 대상이며 GitHub에서는 아래 공개 문서와 정제된 증적만 열 수 있다. 이 결과와 아래 진단 문서는 **실제 로컬 Docker LAB**에서 수집한 동작과 수동 캡처를 근거로 한다. 요청에 사용한 입력과 계정은 실습 데이터다. `examples/integrated-report-sample/`의 공개 보고서 샘플은 합성 데이터이며, 기존 KISA 선정 16개 항목은 별도 인프라 실적이다.

## 결과

| 취약점 | 개선 전 | 개선 후 `4281` | 이번 자동 검증 |
|---|---|---|---|
| `DVWA-SQLI-LOW` · CWE-89 | 원본 `4280`에서 HTTP 200, 5행 | HTTP 400, 0행, 브라우저에 `Invalid user ID.`. 정상 ID당 1행 유지 | 11 통과, 0 실패 |
| `DVWA-XSS-R-LOW` · CWE-79 | 원본 `4280`에서 HTTP 200, `alert(1)` 실행 | HTTP 200, 원문이 화면에 텍스트로 표시, 자동 Chromium에서 팝업·SCRIPT 요소 0건 | 9 통과, 0 실패 |
| `DVWA-UPLOAD-LOW` · CWE-434 | 원본과 코드가 같은 임시 비교본 `4282`에서 TXT HTTP 200 및 공개 저장 | PNG·JPEG HTTP 201, TXT·위장 TXT HTTP 415. 비공개 저장, 거부 9건 저장소 변화 없음 | 17 통과, 0 실패 |

## 취약 원인과 개선

| 취약점 | 원인 | 개선 |
|---|---|---|
| CWE-89 | 사용자 ID를 SQL 문자열에 직접 결합 | 정수 검증 후 Prepared Statement에 바인딩 |
| CWE-79 | `name`을 인코딩 없이 응답 HTML에 삽입 | HTML 텍스트 문맥에서 UTF-8 출력 인코딩 |
| CWE-434 | 유형 검증 없이 클라이언트 파일명으로 웹 루트에 저장 | 확장자·내용 검증, 이미지 재인코딩, 무작위 파일명과 웹 루트 밖 저장 |

## 구현과 증적

- **개인 후속 구현**은 독립 복사본의 SQL 정수 바인딩, Reflected XSS HTML 텍스트 인코딩, 업로드 이미지 검증·비공개 저장과 각 자동 검증기다. DVWA 원본·기본 화면은 업스트림 실습 자산을 사용했다. [SQLi 개선·근거](../audit-evidence-mapping.md#로컬-dvwa-low-sql-injection-개선-재점검) · [SQLi Diff](sqli/low.php.diff) · [XSS 분석](xss-reflected/README.md) · [File Upload 분석](file-upload/README.md)
- **사용자 수동 브라우저**에서 SQLi의 `Invalid user ID.`, XSS의 원본 팝업과 개선본 텍스트 표시, 원본 `4280`의 TXT 반환 경로 및 `4281`의 거부 메시지를 확인했다.
- **사용자 Burp** 캡처에서 원본 SQLi 5행, 개선본 SQLi `400`, 원본 XSS 응답의 스크립트 원문, 개선본 업로드의 `201`·`415`를 확인했다. XSS 개선본의 원시 응답 및 업로드 파일의 실제 저장 상태는 자동 증적으로 판정했다.
- **Codex 자동 재검증**은 실제 HTTP, Chromium, Docker 파일시스템 비교를 실행했다. 최종 JSON은 수동·자동·코드 Diff를 각각 분류하고 경로와 SHA-256을 기록한다. 원본 수동 캡처는 각 `screenshots/`에 있는 로컬 파일을 참조한다. 보고서에는 이미지나 전체 응답 본문, 세션 쿠키를 복사하지 않았다.

## 로컬 재현

저장소 루트에서 실행한다. 원본 SQLi·XSS는 `http://127.0.0.1:4280`, 개선본은 `http://127.0.0.1:4281`, 업로드 전용 비교본은 `http://127.0.0.1:4282`다. 기존 DB 암호를 로컬 환경에서 로드하고, 최초 기동과 임시 DB 초기화는 위 개별 실습 문서를 따른다. File Upload 테스트는 `4282`와 `4281`에만 시험 파일을 작성한다. `requests`, `beautifulsoup4`, `Pillow`, Playwright 및 Chromium, Docker CLI가 필요하다. 각 `--output`에는 새 파일 경로를 지정한다.

```powershell
New-Item -ItemType Directory -Force evidence/dvwa-final | Out-Null
py -3 -B lab/dvwa-sqli-retest/test_http_comparison.py --output evidence/dvwa-final/sqli.json
py -3 -B lab/dvwa-sqli-retest/test_xss_reflected.py --output evidence/dvwa-final/xss.json
py -3 -B lab/dvwa-sqli-retest/test_file_upload.py --output evidence/dvwa-final/upload.json
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py' -v
```

## 전체 회귀와 남은 검증

전체 저장소 unittest 실행 1,269건 중 통과 1,268건, 실패 1건, skip 0건이다. 아래 두 건은 이번 DVWA 재검증과 별도의 기존 환경·원본 증적 문제다. 이와 별도로 `LocalFinalReportTests.setUpClass`에서 `lab/ids-waf-lab/artifacts/`의 원본 세 파일(`day3.pcap`, `suricata-eve.json`, `suricata-fast.log`)이 없어 오류 1건이 발생했다. 이번 실행은 `suricata-fast.log` 누락에서 중단됐고 클래스의 19건은 시작되지 않았다. 실패 1건은 `test_ec2_owner_deployment_script_syntax`의 WSL `/bin/bash` 부재다. 해당 환경과 증적은 보존했다.

File Upload RCE, XSS 개선본 Burp 원시 응답 재점검, 다른 DVWA 보안 수준과 범위 밖 경로는 미검증이다. SQLite HTTP는 이번 실행 범위 밖이다. KISA 16개 결과는 위 수치에 포함하지 않는다.
