# DVWA File Upload 진단 및 개선

## 원인과 분류

DVWA `068d974`의 Low 업로드 화면은 `POST /vulnerabilities/upload/`에서 `Upload`가 설정되면 `$_FILES['uploaded']`를 사용한다. 원본 `low.php`는 클라이언트 파일명에 `basename()`을 적용하고 웹 루트 아래 `hackable/uploads/`의 경로에 붙여 `move_uploaded_file()`로 저장한다. 성공하면 상대 경로가 HTML에 출력된다.

| 검사 영역 | 원본 코드에서 확인한 동작 | 개선 |
|---|---|---|
| 확장자, MIME, 실제 내용 | 확장자 허용 목록, 서버 MIME 감지, 이미지 디코딩이 없다. PHP 업로드 출처 확인 후 파일을 이동한다. | PNG·JPG·JPEG 확장자와 `finfo` 및 이미지 유형을 대조하고 GD 디코딩과 재인코딩을 수행한다. 클라이언트 multipart MIME은 판정에서 제외한다. |
| 크기와 오류 | 폼에 `MAX_FILE_SIZE`가 있고 PHP 자체 한도가 있다. 핸들러에는 별도의 크기·빈 파일 검사와 `$_FILES['error']` 구분이 없다. | 서버에서 실제 바이트가 `1–100000`인지 확인하고 가로·세로를 각각 2048픽셀로 제한한다. 업로드 없음·부분 오류, 크기 위반, 서버 오류에 다른 HTTP 상태를 사용한다. |
| 저장 경로와 파일명 | `basename()`은 디렉터리 구성 요소를 제거한다. 남은 파일명으로 웹 공개 경로에 저장하므로 동일 이름이 충돌할 수 있고 성공 응답이 경로를 노출한다. | 웹 루트 밖 `/var/lib/dvwa-uploads`에 서버 생성 128비트 무작위 ID와 정규화된 확장자로 배타 생성한다. 디렉터리는 `0700`, 파일은 `0600`이다. 절대 경로 대신 파일 ID를 반환한다. |

이미지 기능이 파일 유형을 제한하지 않고 웹에서 직접 조회 가능한 위치에 저장하므로 **CWE-434**로 분류했다. 사용자가 원본 `4280`에서 확인한 파일은 `dvwa-upload-test.txt`이며 응답 경로는 `../../hackable/uploads/dvwa-upload-test.txt`였다. 이번 자동 검증은 원본과 컨테이너 이미지 및 해당 PHP 소스 SHA-256이 같은 임시 비교본 `4282`에서 무해한 TXT의 저장과 HTTP 200 조회를 재현했다. 원본 `4280`에는 업로드 요청을 보내지 않았다. 실행형 파일과 웹셸은 사용하지 않았으며 **RCE는 미검증**이다. [MITRE CWE-434](https://cwe.mitre.org/data/definitions/434.html) · [PHP 업로드 이동 함수](https://www.php.net/manual/en/function.move-uploaded-file.php)

## 실제 검증

2026-11-16 18:35:01 KST에 공통 사례 4건을 두 포트에 같은 multipart 본문으로 전송했다. `4282`는 별도 DB와 임시 네트워크를 사용한다. 개선본 `4281`은 기존 SQLi·XSS 코드를 포함한 이미지에 업로드 처리기를 추가했으며 기존 MariaDB 컨테이너를 재사용한다.

| 요청 | 원본 비교본 `4282` | 개선본 `4281` |
|---|---|---|
| 정상 PNG, JPEG | 각각 200, 웹 루트에 저장, 직접 GET 200 | 각각 201, 비공개 파일 ID, 직접 GET 경로 2곳은 각각 404 |
| TXT 및 PNG로 위장한 TXT | 각각 200, 웹 루트에 저장, 직접 GET 200 | 각각 415, 저장 0건 |
| PNG를 `.jpg`로 제출, 헤더가 남은 잘린 PNG | 미수행 | 각각 415, 저장 0건 |
| 유효 PNG 정확히 100000바이트 | 미수행 | 201, 인코딩된 이미지 1건 저장 |
| 유효 PNG 100001바이트, PHP 업로드 한도 초과, 2049픽셀 너비 | 미수행 | 각각 413, 저장 0건 |
| 0바이트와 파일 미선택 | 미수행 | 각각 400, 저장 0건 |
| 앞서 성공한 PNG와 같은 클라이언트 파일명 | 미수행 | 201, 서로 다른 저장 ID, 기존 파일 유지 |

업로드 테스트 17건에서 기대 결과가 일치했다. 개선본 거부 9건에서 요청 전후의 공개·비공개 저장 디렉터리의 항목, 파일 크기, SHA-256, 권한과 MIME이 동일했다. 기존 SQLi HTTP 11건과 XSS Chromium 9건이 통과했다. 양쪽 Compose 구성 검사, 이미지 빌드 시 업로드 PHP 구문 검사, 비공개 디렉터리 소유권·권한 및 웹 프로세스 쓰기 가능 여부 검사도 통과했다.

자동 검증 이후 사용자 Burp 캡처에서 개선본의 정상 PNG `201`과 TXT `415`를 확인했다. 저장·미저장 판정에는 자동 파일시스템 증적을 사용했다. 원본 캡처는 로컬에 보관한다. [DVWA 최종 재점검](../README.md)

검증 범위는 해당 DVWA 이미지의 Low 모드와 표의 입력이다. RCE, 다른 보안 레벨, 디스크 고갈, 동시 다량 업로드, `post_max_size` 초과 및 웹 서버 장애 주입은 미검증이다. 저장 이미지를 제공하는 다운로드 경로는 구현 범위 밖이다.

## JSON·PDF 보고서 연결

공통 식별자는 `DVWA-UPLOAD-LOW`다. JSON·PDF 생성 시 `report-evidence.json`의 `finding_id`, `cwe`, `assessment`, `limits`를 사용하고 각 증적에 `id`, 상대 `path`, `sha256`을 함께 표시한다. 상대 경로의 기준은 인덱스 파일이 있는 디렉터리다. 배포 소스 SHA-256으로 PHP Diff와 컨테이너를 연결한다. 보고서 인덱스는 저장소의 기존 보고서 생성기와 독립적으로 사용할 수 있다.

- 실제 HTTP 메서드·경로, 파일과 multipart SHA-256, 상태, 응답 발췌와 본문 SHA-256, 테스트별 디스크 및 GET 결과. [HTTP·저장소 증적](http-storage-evidence.json)
- 기존 SQLi와 XSS의 이번 배포 후 실제 회귀 실행 결과. [회귀 증적](regression-evidence.json)
- 실행 중인 원본과 개선본의 `vulnerabilities/upload/source/low.php` 비교와 SHA-256. [PHP 코드 Diff](low.php.diff) · [보고서 증적 인덱스](report-evidence.json)

응답 본문은 테스트 결과에 필요한 발췌만 저장했다. 전체 본문·쿠키·자격 증명은 증적 파일에 넣지 않았다. 본문 해시는 각 실행의 수신 바이트를 식별하며 로그인 세션과 파일 ID에 따라 다음 실행에서 달라질 수 있다.

## 자동 재현

저장소 루트에서 실행한다. 기존 개선본을 재빌드할 때는 기존 `DVWA_RETEST_DB_PASSWORD` 값을 로드한다. 임시 원본 비교본의 DB 암호는 별도로 지정한다.

```powershell
docker compose -f lab/dvwa-sqli-retest/compose.yml config --quiet
docker compose -f lab/dvwa-sqli-retest/compose.yml up -d --build --no-deps web
$env:DVWA_UPLOAD_BASELINE_DB_PASSWORD = [guid]::NewGuid().ToString('N') # 최초 기동 시
docker compose -f lab/dvwa-sqli-retest/compose.upload-baseline.yml up -d
```

새로 기동한 임시 DB는 [4282 Setup](http://127.0.0.1:4282/setup.php)에서 **Create / Reset Database**로 초기화한다. 임시 DB는 컨테이너를 중지하면 초기화가 다시 필요하다. 개선본의 DB 초기화 절차는 기존 SQLi 문서를 따른다. [개선 PHP](../../../lab/dvwa-sqli-retest/file-upload-low.php) · [개선 Compose](../../../lab/dvwa-sqli-retest/compose.yml) · [임시 비교 Compose](../../../lab/dvwa-sqli-retest/compose.upload-baseline.yml) · [기존 실습 구성](../../audit-evidence-mapping.md#로컬-dvwa-low-sql-injection-개선-재점검)

업로드 검증기는 Docker CLI, Python `requests`, `beautifulsoup4`, `Pillow`를 사용한다. XSS 검증에는 Playwright Chromium이 필요하다. 테스트는 무해한 PNG·JPEG·TXT를 메모리에서 생성하고 고유한 이름으로 제출한다. JSON은 기존 파일을 덮어쓰지 않고 새 경로에 기록한다.

```powershell
New-Item -ItemType Directory -Force evidence/dvwa-file-upload | Out-Null
py -3 -B lab/dvwa-sqli-retest/test_file_upload.py --output evidence/dvwa-file-upload/http-storage.json
py -3 -B lab/dvwa-sqli-retest/test_http_comparison.py --output evidence/dvwa-file-upload/sqli.json
py -3 -B lab/dvwa-sqli-retest/test_xss_reflected.py --output evidence/dvwa-file-upload/xss.json
```

## Burp Suite 재점검

1. Burp 브라우저에서 [임시 원본 비교본 로그인](http://127.0.0.1:4282/login.php)과 [개선본 로그인](http://127.0.0.1:4281/login.php)에 `admin` / `password`로 로그인하고 **DVWA Security → Low**로 설정한다. 원본 `4280`에 새 파일을 남기지 않으려면 `4282`를 사용한다.
2. [비교본 업로드 화면](http://127.0.0.1:4282/vulnerabilities/upload/)과 [개선본 업로드 화면](http://127.0.0.1:4281/vulnerabilities/upload/)에서 작은 실제 PNG 또는 JPEG와 무해한 고유 이름의 TXT를 각각 제출한다. **Proxy → HTTP history**에서 `POST /vulnerabilities/upload/`를 골라 **Send to Repeater**한다. 대상 포트에 맞는 `PHPSESSID`와 `security=low`, `multipart/form-data`의 boundary, `Upload=Upload`, `uploaded` 파일 파트를 유지한다.
3. 정상 이미지에서 `4282`의 `200`과 공개 경로, `4281`의 `201`과 `Image uploaded. ID:`를 확인한다. TXT에서 `4282`는 `200`, `4281`은 `415`다. TXT 요청의 파일 파트에서 `filename`의 확장자를 `.png`로, 파트의 `Content-Type`을 `image/png`로 바꾸고 TXT 본문은 유지한다. 개선본은 여전히 `415`다.
4. 개선본이 성공 응답에서 준 ID를 `/hackable/uploads/<ID>`에 붙여 GET하면 `404`다. 파일 저장 여부는 HTTP 404와 별개로 자동 스크립트의 디렉터리 스냅샷에서 확인한다.
