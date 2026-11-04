# 3일차 Suricata IDS·ModSecurity WAF 격리 실습

`infra-day3-lab`은 합성 패킷의 오프라인 탐지와 내부 HTTP 정책 차단을 검증하기 위한 실습 환경이다. 진단 ID는 실습 정책이다. 공식 KISA 항목 번호를 부여하지 않았다.

## 이미지와 서비스

| 서비스 | 이미지 | 역할 |
|---|---|---|
| `suricata` | `jasonish/suricata:8.0.6` | 기본 설정과 로컬 규칙으로 합성 PCAP을 재생하는 일회성 IDS |
| `waf` | `owasp/modsecurity-crs:4.25.2-nginx-202610180210-lts` | ModSecurity와 OWASP CRS로 요청을 검사하고 허용 요청을 `http://backend:8081`로 전달 |
| `backend` | `python:3.12.12-slim-bookworm` | 요청을 저장하지 않고 고정 응답을 반환하는 내부 웹 서버 |
| `client` | `python:3.12.12-slim-bookworm` | 내부 WAF에만 정상 GET과 정책상 금지된 PUT을 보내 응답 확인 |

게시 레지스트리에서 이미지 태그의 존재를 확인했다. [Suricata 태그](https://hub.docker.com/r/jasonish/suricata/tags) · [OWASP 태그](https://hub.docker.com/r/owasp/modsecurity-crs/tags/) · [Python 태그](https://hub.docker.com/layers/library/python/3.12.12-slim-bookworm/images/sha256-2986c55feb36e6cae00fa1fefb454283e4b33f35e75ff8bdd123b134130be301)

OWASP 이미지 시작 시 환경변수가 설정 템플릿에 반영된다. `BACKEND`는 프록시 대상을, `MODSEC_REQ_BODY_ACCESS=On`은 `SecRequestBodyAccess On`을 설정한다. 규칙 엔진은 `On`, 감사 엔진은 `RelevantOnly`, 감사 형식은 `JSON`, 차단·탐지 수준은 1, 인바운드 점수 임계값은 5다. 감사 이벤트는 stdout에 직렬 기록하며 본문 기록용 감사 파트는 지정하지 않는다. [OWASP 이미지 설정 문서](https://github.com/coreruleset/modsecurity-crs-docker#configuration)

## 격리 방식

WAF·백엔드·클라이언트는 Day 3 전용 내부 네트워크만 사용한다. Suricata는 `network_mode: none`이며 기본 이미지 진입점을 거치지 않고 바이너리로 합성 PCAP만 분석한다. 모든 서비스에서 Linux capability를 제거하고 권한 상승을 제한한다. 호스트 포트, Docker 소켓, 기존 DB 및 Day 2 네트워크는 연결하지 않는다. 호스트에서 마운트하는 파일은 로컬 규칙, 합성 PCAP, 두 실습용 Python 파일이며 모두 읽기 전용이다. PCAP과 추출 로그는 Git에서 제외되는 `artifacts/`에 보관한다.

## Windows PowerShell 실행 절차

승인된 로컬 Docker Desktop에서 저장소 루트를 기준으로 실행한다. 이미지가 없으면 첫 실행 시 게시 레지스트리에서 내려받는다. IDS·WAF 테스트 자체는 외부 시스템에 요청을 보내지 않는다.

```powershell
.\.venv\Scripts\python.exe -B lab/day3/suricata/make_pcap.py
Set-Location lab/day3
docker compose -p infra-day3-lab --profile tools config --quiet
docker compose -p infra-day3-lab --profile tools config --services
docker compose -p infra-day3-lab --profile tools config --images
```

### IDS 설정 검사와 오프라인 탐지

PCAP 생성기는 문서용 IP의 UDP 프레임 두 개를 파일에 기록한다. 하나는 정상 대조군, 다른 하나는 실습 문자열을 담는다. 이미지 기본 EVE alert 설정을 사용하고 `HOME_NET`은 합성 목적지 대역 `198.51.100.0/24`로 지정한다. `-S`는 지정한 로컬 규칙만 로드한다. [Suricata 명령행 옵션](https://docs.suricata.io/en/suricata-8.0.6/command-line-options.html)

```powershell
docker compose -p infra-day3-lab run --rm --no-deps suricata -V
docker compose -p infra-day3-lab run --rm --no-deps suricata --dump-config
docker compose -p infra-day3-lab run --rm --no-deps suricata -T
if ($LASTEXITCODE -ne 0) { throw 'Suricata configuration check failed' }
docker compose -p infra-day3-lab up -d --no-deps --force-recreate suricata
if ($LASTEXITCODE -ne 0) { throw 'Suricata replay startup failed' }
docker compose -p infra-day3-lab wait suricata
if ($LASTEXITCODE -ne 0) { throw 'Suricata replay failed' }
docker compose -p infra-day3-lab cp suricata:/tmp/eve.json artifacts/eve.json
if ($LASTEXITCODE -ne 0) { throw 'EVE log copy failed' }
$idsAlerts = @(Get-Content artifacts/eve.json | ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object { $_.event_type -eq 'alert' -and $_.alert.signature_id -eq 1000003 })
if ($idsAlerts.Count -ne 1) { throw 'Expected exactly one synthetic IDS alert' }
$idsAlerts | Select-Object event_type, @{Name='sid';Expression={$_.alert.signature_id}}
```

SID `1000003` 이벤트 한 건은 합성 문자열 탐지 증적이다. 실제 공격 탐지 결과와는 별도로 기록한다.

### WAF 설정 검사와 내부 정책 차단

```powershell
docker compose -p infra-day3-lab up -d backend waf
docker compose -p infra-day3-lab ps
docker compose -p infra-day3-lab exec -T waf nginx -T
$probeJson = docker compose -p infra-day3-lab run --rm --no-deps client
if ($LASTEXITCODE -ne 0) { throw 'WAF HTTP check failed' }
$probe = $probeJson | ConvertFrom-Json
$probe
$wafAudit = @(docker compose -p infra-day3-lab logs --no-log-prefix --no-color waf |
    Where-Object { $_ -match '^\s*\{' } | ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object {
        $_.transaction.request.uri -eq "/day3-policy?run=$($probe.run)" -and
        $_.transaction.response.http_code -eq 403 -and
        $_.transaction.messages.details.ruleId -contains '911100'
    })
if ($wafAudit.Count -eq 0) { throw 'Matching CRS audit event not found' }
$wafAudit | ForEach-Object { $_ | ConvertTo-Json -Depth 20 -Compress } |
    Set-Content -Encoding utf8 artifacts/waf-audit.jsonl
```

정상 GET에서 백엔드 표식과 HTTP 200을 확인한 다음, 데이터 변경이 없는 PUT에서 HTTP 403을 확인한다. 감사 로그에서도 같은 실행 ID와 CRS 메서드 규칙 `911100`을 대조한다. 이 실습의 검증 범위는 메서드 정책 차단이다. 본문 기반 탐지와 실제 공격 방어 성능은 별도 검증이 필요하다. [CRS 4.25.2 메서드 규칙](https://github.com/coreruleset/coreruleset/blob/v4.25.2/rules/REQUEST-911-METHOD-ENFORCEMENT.conf)

종료 시 해당 프로젝트만 정리한다.

```powershell
docker compose -p infra-day3-lab --profile tools down
```

## 예정된 진단 기준

| ID | 구분 | 실습 기준 및 증적 |
|---|---|---|
| IDS-01 | 설정 | 유효 설정에서 EVE JSON 활성화 및 출력 경로 확인 |
| IDS-02 | 설정 | EVE 이벤트 유형에 `alert` 포함 확인 |
| IDS-03 | 설정 | `HOME_NET`이 승인된 합성 목적지 대역과 일치하는지 확인 |
| IDS-04 | 설정 | 지정 로컬 규칙과 SID 로드 성공 및 규칙 오류 여부 확인 |
| IDS-05 | 설정 | 동일 설정과 규칙으로 `suricata -T` 종료 코드 확인 |
| IDS-06 | 동작 | 합성 PCAP 재생 후 EVE에서 지정 테스트 SID 확인 |
| WAF-01 | 설정 | 유효 `SecRuleEngine On` 확인 |
| WAF-02 | 설정 | `SecAuditEngine RelevantOnly` 및 감사 출력 위치 확인 |
| WAF-03 | 설정 | `SecAuditLogFormat JSON` 확인 |
| WAF-04 | 설정 | `SecRequestBodyAccess On` 확인 |
| WAF-05 | 설정 | 실제 CRS 포함 경로, 차단 수준 1 및 인바운드 임계값 5 확인 |
| WAF-06 | 동작 | 정상 요청의 백엔드 도달, 정책 요청의 403, 해당 실행의 CRS 감사 이벤트 확인 |

향후 수집기는 Compose 선언과 실제 유효 설정을 구분한다. IDS는 `--dump-config`와 `-T`를, WAF는 `nginx -T` 및 실제 포함된 ModSecurity·CRS 파일을 읽는다. 설정 관찰과 동작 시험의 증적은 분리한다. 수집 실행 전에 승인된 프로젝트·서비스를 검증하고, 원격 자산에 연결할 때는 기존 Scope 정책을 적용한다.
