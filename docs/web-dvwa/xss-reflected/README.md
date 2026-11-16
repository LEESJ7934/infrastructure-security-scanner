# DVWA Reflected XSS 재점검

## 원인과 개선

DVWA `068d974`의 Low 모드에서 `vulnerabilities/xss_r/index.php`가 `source/low.php`를 불러온다. 공격자가 제어하는 GET `name`이 `$_GET['name']`에서 `$html`의 `<pre>Hello …</pre>`에 문자열 결합으로 들어가고, `index.php`가 이를 `$page['body']`에 삽입해 HTML 응답으로 반환한다. `<pre>` 안에서도 태그는 HTML로 해석된다. 원본은 HTML 출력 인코딩을 수행하지 않아 `<script>alert(1)</script>`가 스크립트 요소로 해석되고 DVWA 페이지의 출처에서 실행됐다. 원본의 `X-XSS-Protection: 0`은 브라우저의 레거시 필터와 관련된 헤더다. [MITRE CWE-79](https://cwe.mitre.org/data/definitions/79.html)

개선 처리기는 `name`이 비어 있지 않은 문자열일 때 그 값을 `htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`로 변환한 뒤 HTML 텍스트 위치에 넣는다. `ENT_QUOTES`는 두 종류의 따옴표를 인코딩하고, `ENT_SUBSTITUTE`는 잘못된 UTF-8 바이트를 대체 문자로 표시한다. 배열 입력으로는 인사말을 생성하지 않는다. [개선 PHP 코드](../../../lab/dvwa-sqli-retest/xss-reflected-low.php) · [PHP 매뉴얼](https://www.php.net/manual/en/function.htmlspecialchars.php)

기존 [Dockerfile](../../../lab/dvwa-sqli-retest/Dockerfile)에 Reflected XSS Low 파일의 복사와 구문 검사를 추가했다. 원본 `4280`과 개선본 `4281`은 각각 기존 포트를 사용한다. 기존 [Compose 구성](../../../lab/dvwa-sqli-retest/compose.yml)과 DB 볼륨으로 `4281`의 웹 컨테이너만 다시 빌드했다. 원본 웹과 개선본 DB의 컨테이너 ID가 재빌드 전후에 일치했고, 개선본의 SQLi PHP 파일 SHA-256도 일치했다.

## 실제 검증 결과

2026-11-16 18:18:21 KST에 Playwright Chromium `145.0.7632.6`으로 두 포트에서 Low 세션을 각각 열었다. 공통 사례 3개의 메서드, URL 경로와 쿼리, Low 쿠키 값이 일치했다. 각 요청은 새 페이지에서 로드했고, 로드가 끝날 때까지 브라우저가 발생시킨 대화상자와 인사말의 화면 텍스트·DOM을 검사했다.

| 입력 | 원본 `4280` | 개선본 `4281` |
|---|---|---|
| `test123` | HTTP 200, `Hello test123` | HTTP 200, `Hello test123` |
| `<script>alert(1)</script>` | HTTP 200, 응답에 원문 태그, DOM에 `SCRIPT`, `alert(1)` 1회 | HTTP 200, 응답에 `&lt;script&gt;alert(1)&lt;/script&gt;`, DOM에 태그 없음, 원문이 화면에 표시, 팝업 0회 |
| `Tom & "O'Reilly"` | HTTP 200, 화면에서 원문 유지 | HTTP 200, 응답은 특수문자 인코딩, 화면에서 원문 유지 |
| `&lt;script&gt;` | 미수행 | HTTP 200, 입력의 앰퍼샌드가 인코딩되고 입력 문자열이 화면에 그대로 표시 |
| `name[]=test123` | 미수행 | HTTP 200, 인사말 없음 |
| `name=%FF` | 미수행 | HTTP 200, `Hello �` 표시 |

Chromium·HTTP 기대값 비교 9건과 Compose 구성 검사, 이미지 빌드 시 PHP 구문 검사가 통과했다. 기존 SQLi HTTP 회귀 테스트도 11건 통과했다. 두 포트의 정상 ID `1`, `2`는 각각 동일한 사용자 1행을 반환했고, SQLi 입력은 원본에서 `200`과 5행, 개선본에서 `400`과 0행을 반환했다.

사용자가 제공한 원본 Burp 응답 및 브라우저 팝업 관찰은 별도 수동 기록이다. 이번 실행에서 Chromium으로 원본 팝업을 재현했다. 개선본 Burp 수동 재점검은 미수행이다. 자동 결과의 범위는 해당 DVWA 버전의 Reflected XSS Low GET 경로, 표의 입력 및 Chromium이다. 다른 브라우저, 다른 보안 수준, Stored XSS·DOM XSS 및 다른 출력 위치는 미검증이다.

## 증적과 배포 소스

- 실제 요청 메서드·경로·쿼리, 상태, 본문 길이·SHA-256, 알려진 실습 인사말 발췌와 DOM·대화상자 관찰을 보관한다. 본문 전체와 인증 정보는 저장하지 않았다. 본문 해시는 해당 요청에서 읽은 바이트를 식별한다. JSON SHA-256 `60af126deaf4353c6d0d0709597b35d64729a2af504ffe70d502a8230b9095f9`. [HTTP·브라우저 증적](http-browser-evidence.json)
- 원본과 개선본의 `/var/www/html/vulnerabilities/xss_r/source/low.php`를 실행 컨테이너에서 복사해 비교했다. 원본 SHA-256 `fb3c6fd9937697d4473cb9a2a9267df44b7e8620b16a4189189e76455d351833`, 개선본 SHA-256 `d5919e92933f7d71ff23e39fc8eab00bcefdb9232937f7d59fd235137b198987`. 개선본 해시는 저장소의 PHP 파일과 일치한다. Diff SHA-256 `3e2ebcea1a0c77a29918ae7b3187cdf20acab3438d93c887ebb098b78eea52dd`. [배포 코드 Diff](low.php.diff)

## 자동 재현

원본 `4280`과 복사본 `4281`의 DB가 초기화된 환경에서 저장소 루트 기준으로 실행한다. 기존 복사본을 재빌드할 때는 처음 사용한 `DVWA_RETEST_DB_PASSWORD`를 로드한다. 아래 테스트는 `requests`, `beautifulsoup4`, `playwright`와 해당 Chromium 브라우저를 사용한다. Playwright 브라우저 준비 명령은 `py -3 -m playwright install chromium`이다. 필요한 경우 원본 로그인 정보는 `DVWA_BEFORE_USERNAME`, `DVWA_BEFORE_PASSWORD`로 지정한다.

```powershell
docker compose -f lab/dvwa-sqli-retest/compose.yml config --quiet
docker compose -f lab/dvwa-sqli-retest/compose.yml up -d --build --no-deps web
New-Item -ItemType Directory -Force evidence/dvwa-xss-reflected | Out-Null
py -3 -B lab/dvwa-sqli-retest/test_xss_reflected.py --output evidence/dvwa-xss-reflected/http-browser-recheck.json
py -3 -B lab/dvwa-sqli-retest/test_http_comparison.py --output evidence/dvwa-xss-reflected/sqli-regression.json
```

결과 파일은 새 경로에만 생성한다. 해당 스크립트는 응답이나 브라우저 관찰이 기대값과 다르면 0이 아닌 상태로 종료한다. 새 복사본의 최초 DB 기동과 초기화 절차는 기존 SQLi 실습 문서에 있다. [XSS 자동 검증](../../../lab/dvwa-sqli-retest/test_xss_reflected.py) · [SQLi 자동 검증](../../../lab/dvwa-sqli-retest/test_http_comparison.py) · [복사본 초기화](../../audit-evidence-mapping.md#로컬-dvwa-low-sql-injection-개선-재점검)

## Burp Suite 재점검

1. **Proxy → Open browser**에서 포트별로 로그인한 뒤 **DVWA Security**를 **Low**로 설정한다. 개선본의 기본 실습 로그인은 `admin` / `password`다. [원본 로그인](http://127.0.0.1:4280/login.php) · [개선본 로그인](http://127.0.0.1:4281/login.php)
2. 각 Reflected XSS 화면에서 `test123`을 제출하고 **Proxy → HTTP history → Send to Repeater**로 보낸다. Repeater 목적지와 각 탭의 `PHPSESSID`가 캡처한 `4280` 또는 `4281` 세션의 것인지 확인한다. 두 포트 모두 쿠키에 `security=low`가 필요하다. [원본 XSS 화면](http://127.0.0.1:4280/vulnerabilities/xss_r/) · [개선본 XSS 화면](http://127.0.0.1:4281/vulnerabilities/xss_r/)
3. 각 Repeater 탭에서 아래 요청을 순서대로 보낸다. 정상 요청은 두 곳 모두 `Hello test123`이다. XSS 요청에서 원본 응답은 `<script>alert(1)</script>`를 포함하고 개선본 응답은 `&lt;script&gt;alert(1)&lt;/script&gt;`를 포함한다.

   ```http
   GET /vulnerabilities/xss_r/?name=test123 HTTP/1.1
   GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1
   ```

4. 팝업을 확인하려면 각 포트의 로그인된 **Burp 브라우저** 주소창에서 XSS 쿼리가 붙은 URL을 연다. 원본에서 `alert(1)`, 개선본에서 팝업 없이 `Hello <script>alert(1)</script>`가 화면에 표시되는 것이 기대값이다. 포트 전환 후 로그인 화면이 나타나면 그 포트에서 다시 로그인해 Low를 확인한다.
