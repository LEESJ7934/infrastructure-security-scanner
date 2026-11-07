# Phase2 Nginx / Tomcat 개인 LAB

이번 구현은 오프라인 코드·테스트·보고서 준비 단계이다. 실제 이미지 다운로드, 빌드, 컨테이너 실행 및 설정 개선은 아래 사용자 PowerShell 실행 단계로 분리한다. 기존 Windows Server, Router/Switch, Day1~5 환경을 변경하지 않는다. KISA 공식 항목이나 인증이 아닌 내부 `WEB-WAS-LAB-0.1` 기준이다.

## 보존과 브랜치

브랜치: `feature/phase2-web-was` (기존 HEAD 5724bff에서 분기). 기존 미커밋 파일은 작업 트리에 그대로 유지하며 commit/stash/reset하지 않았다. 별도 비공개 로컬 백업 ZIP 및 원본 SHA-256 목록을 Codex 작업 디렉터리 `work/pre-web-was-checkpoint/`에 작성했다. 이 백업은 공개 저장소 산출물이 아니다. 기존 네트워크/Windows JSON은 읽기 전용 해시 확인만 수행한다.

## 제품과 격리 환경

- Nginx: `nginx:1.30.6-alpine` (공식 이미지 목록의 stable 계열).
- Tomcat: `tomcat:10.1.61-jdk21-temurin-noble` (10.1 계열 / Java 21).
- 출처: [Nginx 공식 이미지 목록](https://github.com/docker-library/official-images/blob/master/library/nginx), [Tomcat 공식 이미지 목록](https://github.com/docker-library/official-images/blob/master/library/tomcat).
- 태그는 버전 고정이며 digest 고정은 아니다. 실제 다운로드 시 가용성을 확인하고, 수집 결과에 실제 실행 image ID와 제품 버전을 기록한다. 태그 존재/빌드 성공은 아직 실환경 검증하지 않았다. 실패 시 임의의 latest 이미지로 대체하지 않는다.
- 별도 Compose 프로젝트 `scanner-p2web`, internal bridge `scanner-p2web_backend`. 호스트 포트, bind mount, privileged, 추가 capability 없이 비 root UID/GID 10001로 실행한다. 이미지 rootfs는 읽기 전용이고 쓰기 작업은 제한된 tmpfs에서만 허용한다.
- 메모리 제한 Nginx 128MB, Tomcat 384MB. 호스트에 Java, Nginx, Tomcat을 설치할 필요가 없다. Docker Desktop Linux 컨테이너, Compose v2 및 기존 Python venv가 필요하다.
- 외부 통신은 이미지 pull/build 시 사용자 Docker가 수행한다. 실행 네트워크는 internal이며 기존 Docker 전역 방화벽/daemon/VM을 수정하지 않는다. internal bridge만으로 Docker 호스트와 완전히 격리됐다고 주장하지 않는다.

## 점검 항목

| 항목 | 내부 LAB 기준 | 최초 템플릿 | 개선 템플릿 |
|---|---|---|---|
| WEB-LAB-N01 | /files/ 디렉터리 목록 차단 | autoindex on | off + HTTP 403/404 |
| WEB-LAB-N02 | 응답의 Nginx 버전 숨김 | server_tokens on | off + 지정 응답 버전 비노출 |
| WEB-LAB-N03 | 불필요한 /private/ 접근 차단 | 무해한 테스트 파일 노출 | 404 + 실제 요청 차단 |
| WEB-LAB-N04 | 접근 로그 활성화와 현재 요청 기록 | off | 전용 로그 + 실행별 marker 확인 |
| WAS-LAB-T01 | Host 자동 배포 비활성화 | autoDeploy=true | false (deployOnStartup=true 유지) |
| WAS-LAB-T02 | 활성 appBase 기본 앱 제거 | 실제 docs/examples 복사 | docs/examples/manager/host-manager 부재 |
| WAS-LAB-T03 | 오류의 서버 정보 숨김 | ErrorReportValve 정보 노출 | showReport/showServerInfo=false + 응답 확인 |
| WAS-LAB-T04 | 접근 로그 활성화와 현재 요청 기록 | Valve 없음 | AccessLogValve + 현재 marker 확인 |

최초 템플릿은 합성 테스트에서 FAIL 8개, 개선 템플릿은 PASS 8개이다. 실제 최초/재점검 결과는 사용자 실행 이후 생성되는 JSON으로만 확정한다. 기본 manager/host-manager는 처음부터 활성화하지 않으며 사용자/암호를 만들지 않는다. docs/examples 존재는 불필요한 기본 앱 점검의 재현 범위이다.

Nginx는 include 없는 제공 LAB 템플릿 두 개만 인식한다. 알 수 없는 override/include/context는 NEEDS_REVIEW이며 범용 Nginx 파서로 주장하지 않는다. Tomcat도 단일 Service/Engine/Host/Connector와 지원하는 Valve 구조만 해석한다. 누락값은 안전한 기본값으로 채우지 않는다. 제품 문서의 기본값, 명시 설정값 및 실제 HTTP 관찰을 구분하며, PASS는 지원 버전의 확인값에만 허용한다. 미수행은 NOT_TESTED, 미확인/미지원 버전은 NEEDS_REVIEW, 수집 실패는 ERROR이다. 이 LAB에서는 8개 모두 적용 대상으로 설계했으며 다른 제품을 실제 검증했다고 주장하지 않는다.

## 1. 실행 전 준비 (사용자 실행)

프로젝트 루트 PowerShell에서 실행한다. 이번 Codex 작업에서는 다음 build/up 명령을 실행하지 않았다.

```powershell
Set-Location C:\Projects\infrastructure-security-scanner-clone
docker info --format '{{.OSType}}'
docker compose version
docker compose -f .\lab\phase2-web-was\compose.json config --quiet
New-Item -ItemType Directory -Force .\logs\phase2-web-was, .\reports\phase2-web-was | Out-Null
.\.venv\Scripts\python.exe -B -m scripts.run_web_was_audit
```

기본 실행은 Docker에 접속하지 않고 8개 NOT_TESTED 및 HTTP NOT_TESTED를 표시한다. JSON/PDF에 필요한 reportlab/pypdf는 기존 venv를 사용한다. 설치되지 않은 경우 기존 프로젝트 의존성부터 확인한다. 이번 작업에서 추가 패키지를 설치하지 않았다.

## 2. 최초 취약 설정 수집 (사용자 실행)

```powershell
$env:WEB_WAS_STAGE = 'before'
docker compose -f .\lab\phase2-web-was\compose.json build --pull
docker compose -f .\lab\phase2-web-was\compose.json up -d --no-build
docker compose -f .\lab\phase2-web-was\compose.json ps
Start-Sleep -Seconds 15
.\.venv\Scripts\python.exe -B -m scripts.run_web_was_audit --execute --output .\logs\phase2-web-was\before.json --pdf .\reports\phase2-web-was\before.pdf
```

각 명령에서 오류가 나면 다음 단계로 넘어가지 않는다. 최초 결과가 FAIL 8개 및 HTTP PASS인지 실제 JSON을 확인한다. 아직 기동 중이라면 로그를 확인하고 정상화 후 **새 출력 파일명**으로 재수집한다. HTTP는 Tomcat 컨테이너의 컴파일된 Java helper가 내부 Nginx에 요청하고, Tomcat JSP의 본문 marker 및 `X-Lab-Backend`를 대조한다. 호스트 포트는 필요하지 않다.

## 3. LAB 내부 설정 개선 (사용자 실행)

설정은 이미지 내부에 포함하므로 새 LAB의 두 서비스만 개선 이미지로 재생성한다. 이전 컨테이너 tmpfs 로그는 사라지므로 반드시 최초 JSON 수집을 마친 후 실행한다. 기존 다른 LAB에는 영향을 주지 않는다.

```powershell
$env:WEB_WAS_STAGE = 'after'
docker compose -f .\lab\phase2-web-was\compose.json build
docker compose -f .\lab\phase2-web-was\compose.json up -d --no-build --force-recreate
docker compose -f .\lab\phase2-web-was\compose.json ps
Start-Sleep -Seconds 15
```

이 명령이 실제 변경 단계이며 Python 수집기는 설정을 변경하지 않는다. 별도의 조직 승인 문서/독립 기대 해시가 없다는 이유로 개인 LAB 판정을 차단하지 않는다.

## 4. 재점검 및 JSON/PDF 생성 (사용자 실행)

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_web_was_audit --execute --baseline-json .\logs\phase2-web-was\before.json --output .\logs\phase2-web-was\after.json --pdf .\reports\phase2-web-was\after.pdf
```

실제 FAIL→PASS 및 개선 전후 HTTP PASS가 확인돼야 조치·재점검 완료로 기록한다. 제품 버전 차이, 시각 역전 또는 HTTP 경로 미확인이 있으면 비교는 INCOMPARABLE이다. 실제 관찰을 같은 내부 규칙으로 재평가한 LAB 비교이며 기존 Day5 엄격 비교 엔진을 바꾸지 않는다. before/after는 같은 논리 LAB 서비스이며 컨테이너/image ID는 재생성 시 바뀔 수 있다.

기존 파일은 덮어쓰지 않는다. 재실행 시 after-v2.json/after-v2.pdf처럼 새 이름을 사용한다. 선택적 오프라인 재분석:

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_web_was_audit --input-json .\logs\phase2-web-was\after.json --baseline-json .\logs\phase2-web-was\before.json --output .\reports\phase2-web-was\offline-analysis.json --pdf .\reports\phase2-web-was\offline-analysis.pdf
```

수집 시각은 원본 bundle.collected_at으로 유지하며 generated_at/checked_at은 분석 시각이다. 재분석을 새로운 실제 시험으로 주장하지 않는다.

## 보고서와 증적

- AuditAsset/AuditRule/Observation 및 기존 evaluate()를 그대로 사용한다.
- `as_snapshot()` / `common_snapshot()`으로 Day5 ReportResult/SourceSnapshot에 연결한다. day=0은 Phase2 별도 출처이고 기존 Day5 실제 보고서에 자동 삽입하지 않는다. manual=None이며 자동 판정과 수동 결과를 합치지 않는다.
- JSON: 실제 버전/image ID, 시작·수집·분석 시각, 설정의 최소 불리언 관찰값, 설정 SHA-256, HTTP 결과, 내부 기준/조치 방안, 비교와 한계.
- 시작 당시 설정 hash와 읽기 전용 rootfs의 현재 설정 hash를 대조하고 Nginx 구문 검사를 수행한다. 해시는 출처 진위나 모든 실행 정책의 완전성 증명이 아니다.
- 현재 실행에서 생성한 HTTP marker가 각 접근 로그에 있는지 확인한다. 과거 로그 존재만으로 PASS하지 않는다. 원본 설정/로그/HTTP 본문/인증 헤더는 파일이나 보고서에 저장하지 않는다.
- 원본 로그는 수집 중 컨테이너 메모리에서 읽고 marker 존재 여부만 남긴다. 보고서에는 자격증명·개인키가 없다.
- 이번에 제공한 합성 JSON/PDF는 `origin=synthetic`과 문서 제목으로 명확히 표시한다. 실제 조치 완료는 false이다.

## 테스트와 문제 대응

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_web_was_audit
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
docker compose -f .\lab\phase2-web-was\compose.json ps -a
docker compose -f .\lab\phase2-web-was\compose.json logs --tail 40
```

Docker 직접 접근이 불가능하면 사용자가 위 명령을 실행하고 저장된 JSON을 오프라인 분석한다. 오류 메시지는 고정 코드이며 raw stderr를 노출하지 않는다. 최초 JSON을 얻지 못했다면 baseline을 만들어 내지 않는다. 실제 태그 pull, 이미지 빌드, Tomcat JSP 컴파일, 비 root 실행, HTTP, 현재 로그 기록 및 실제 FAIL→PASS는 사용자 실행 단계의 미검증 항목이다.

실습 종료 시 새 LAB만 종료:

```powershell
docker compose -f .\lab\phase2-web-was\compose.json down
Remove-Item Env:WEB_WAS_STAGE -ErrorAction SilentlyContinue
```

Docker 전체 prune/down, 호스트 방화벽 변경, 기존 VM/네트워크 변경은 필요하지 않다.

## 기준 문서

- [Nginx autoindex](https://nginx.org/en/docs/http/ngx_http_autoindex_module.html)
- [Nginx server_tokens](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens)
- [Nginx access_log](https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log)
- [Tomcat Host / automatic deployment](https://tomcat.apache.org/tomcat-10.1-doc/config/host.html)
- [Tomcat ErrorReportValve / AccessLogValve](https://tomcat.apache.org/tomcat-10.1-doc/config/valve.html)
- [Tomcat Connector server attribute](https://tomcat.apache.org/tomcat-10.1-doc/config/http.html)

제품 지시어 의미는 공식 문서를 참고했고 양호 기준은 이 프로젝트가 정의한 개인 실습 기준이다. 기본값 문서와 실제 적용값을 혼동하지 않는다.
