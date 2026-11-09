# Suricata IDS 및 ModSecurity WAF 격리 실습

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
.\.venv\Scripts\python.exe -B lab/ids-waf-lab/suricata/make_pcap.py
Set-Location lab/ids-waf-lab
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

## 실습 진단 기준 (역사적)

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


> 다음은 과거 격리 실습에서 저장했던 결과다. **Suricata IDS/IPS는 현행 최종 실측 성과에 포함하지 않는다.** 당시 원본 `logs/day3-final.json`과 `lab/ids-waf-lab/artifacts/`는 Git에 없을 수 있다. 아래 PASS는 당시 실습의 제한된 범위이며 현재 재실행·독립 검증된 판정이 아니다.

## 과거 Day3 실습 개발·검증 기록

### 1. 실습 목표와 구성

Suricata IDS의 유효 설정과 오프라인 탐지, ModSecurity WAF의 유효 설정과 내부 HTTP 정책 차단을 검증하고, 결과를 기존 `config_audit` 판정 엔진에 연결했다.

실습 프로젝트는 `infra-day3-lab`이다. Suricata는 `jasonish/suricata:8.0.6` 이미지에서 `suricata` 사용자로 실행한다. WAF는 `owasp/modsecurity-crs:4.25.2-nginx-202610180210-lts` 이미지를 사용한다. Suricata에는 네트워크를 연결하지 않으며, WAF·테스트 백엔드·클라이언트는 실습 전용 내부 네트워크를 사용한다. 호스트 포트를 공개하지 않고 기존 Day 2 및 DB 네트워크와 분리했다.

| 신규 파일 | 실제 구현 내용 |
|---|---|
| [config_audit/collectors/suricata.py](../../config_audit/collectors/suricata.py) | 유효 EVE 설정과 `HOME_NET`, 규칙 로드 집계, EVE의 SID 및 패킷 번호를 해석한다. |
| [config_audit/collectors/modsecurity.py](../../config_audit/collectors/modsecurity.py) | Include 구조, 렌더링된 설정, CRS 임계값과 로드 기록을 확인하고 요청 ID로 감사 이벤트를 대조한다. |
| [scripts/run_ids_waf_audit.py](../../scripts/run_ids_waf_audit.py) | `--execute` 승인 후 로컬 실습 대상을 검증하고 증적을 수집한다. 12개 관찰값을 기존 `evaluate()`로 평가해 JSON을 출력한다. |
| [tests/test_ids_waf_audit.py](../../tests/test_ids_waf_audit.py) | Docker subprocess를 모의 처리하는 테스트 22개를 포함한다. 최초 14개에 Include Chain 회귀 테스트 8개를 추가했다. |
| [lab/ids-waf-lab/](../../lab/ids-waf-lab/) | Compose 환경, 합성 PCAP 생성기와 로컬 규칙, 고정 응답 백엔드와 내부 요청 클라이언트, 실행 안내 및 산출물 제외 규칙을 포함한다. |

### 2. Suricata IDS 설정과 탐지 검증

생성기는 정상 대조군과 실습 문자열을 담은 UDP 패킷을 각각 한 개씩 합성 PCAP에 기록한다. 자동 실행기는 PCAP 해시와 로컬 규칙 SID를 확인하고, 매 실행마다 새 네트워크 차단 컨테이너에서 `--dump-config`, `-T`, 오프라인 재생을 수행한다. 재생은 설정 검사를 통과했을 때 진행하며 이번 실행에서 생성한 `/tmp/eve.json`을 읽는다. 합성 패킷의 2023년 시각과 진단 결과의 UTC `checked_at`은 별도로 기록된다.

수동 실습의 EVE 증적에는 이벤트 3건과 경보 1건이 있다. 경보는 두 번째 패킷의 SID `1000003`이며, Fast 로그에서도 같은 SID를 확인했다. SID `1000003`과 서명 `DAY3 LAB synthetic marker`는 합성 입력의 실습용 규칙이다. 이 결과는 IDS의 오프라인 탐지 검증이며, 트래픽을 경유시켜 막는 IPS 인라인 차단은 검증하지 않았다.

### 3. ModSecurity WAF 설정과 차단 검증

자동 실행기는 WAF와 백엔드의 프로젝트·서비스 라벨, 내부 네트워크, 호스트 포트 미공개 및 프록시 대상을 확인한다. `nginx -T`와 실제 포함된 ModSecurity·CRS 설정을 읽고, 환경변수 선언만으로 통과를 판정하지 않는다.

사용자가 수행한 Docker 실습에서 정상 GET은 HTTP 200과 백엔드 표식을 반환했고, 정책상 허용되지 않는 PUT은 HTTP 403을 반환했다. 같은 요청의 JSON 감사 이벤트에서 허용되지 않은 메서드를 탐지한 `911100`과 인바운드 이상 점수에 따른 차단 규칙 `949110`을 확인했다. 자동 실행기도 고유 요청 ID, HTTP 응답, 두 규칙의 감사 기록을 함께 요구한다. 검증 범위는 내부 메서드 정책 차단이다. 전체 웹 취약점 진단, 요청 본문 기반 공격 탐지, 실제 공격 대응 성능은 검증하지 않았다.

### 4. 12개 실습 점검 결과

아래 ID는 실습용이며 공식 KISA 점검항목 번호가 아니다. 최종 자동 진단의 PASS는 이 실습 환경과 기준에 한정된다.

| ID | 구분 | 판정 근거 | 최종 결과 |
|---|---|---|---|
| IDS-01 | 설정 | 유효 EVE 로깅 활성화, 일반 파일 출력, 파일명 `eve.json` | PASS |
| IDS-02 | 설정 | 유효 EVE 출력 유형에 `alert` 활성화 | PASS |
| IDS-03 | 설정 | `HOME_NET`이 합성 목적지 대역 `198.51.100.0/24`로 제한 | PASS |
| IDS-04 | 설정 | 지정 SID와 실제 규칙 로드 집계가 일치하고 실패·건너뜀 없음 | PASS |
| IDS-05 | 설정 | `suricata -T` 정상 종료 | PASS |
| IDS-06 | 동작 | 이번 재생의 EVE에서 두 번째 패킷의 지정 SID 경보 한 건과 첫 번째 대조군의 무경보 확인 | PASS |
| WAF-01 | 설정 | Nginx의 ModSecurity 활성화 및 포함 설정의 `SecRuleEngine On` | PASS |
| WAF-02 | 설정 | 렌더링된 `SecAuditEngine RelevantOnly` | PASS |
| WAF-03 | 설정 | 렌더링된 `SecAuditLogFormat JSON` | PASS |
| WAF-04 | 설정 | 렌더링된 `SecRequestBodyAccess On` | PASS |
| WAF-05 | 설정 | 실제 CRS 포함 경로와 규칙 로드 기록, 차단 수준 1, 인바운드 임계값 5 | PASS |
| WAF-06 | 동작 | 백엔드 표식을 포함한 GET 200, PUT 403, 같은 요청 ID의 감사 이벤트에 규칙 911100·949110 포함 | PASS |

### 5. Include Chain 오류와 수정

최초 자동 진단에서 IDS 6개는 통과했지만 WAF 6개는 `include_chain_unverified`로 `NEEDS_REVIEW`가 됐다. 기존 검증기는 필수 Include 4개와 정확히 일치하는 구성만 허용했다. 실제 이미지에서는 공식 플러그인의 `config`, `before`, `after` Include가 활성화되어 7개였다.

필수 경로 4개를 유지하고 공식 플러그인 glob을 지정된 위치에서만 허용하도록 수정했다. `config`와 `before`는 CRS 규칙 앞, `after`는 뒤에 있어야 한다. 필수 경로 누락, 임의 경로, 중복, 순서 위반 및 예상 밖 중첩 Include는 거부한다. 플러그인 Include가 비활성화된 구성은 허용하며, 실제 로드 오류는 `nginx -T` 실패로 구분한다. Include 검증을 통과한 뒤에도 유효 설정, CRS 로드 기록, HTTP·감사 증적을 별도로 확인한다.

### 6. 테스트와 증적

- 사용자가 Windows PowerShell에서 **전체 381개 단위 테스트 통과**를 최종 확인했다. 기존 359개에는 앞선 프로젝트 기능의 단위 테스트가 포함되며, Day 3에서 추가한 테스트는 22개다.
- 앞선 Codex 실행에서는 Day 3 테스트 22개가 통과했다. 전체 실행은 Git Bash 초기화와 로컬 루프백 연결 제한으로 기존 테스트 5개가 실패했다. 문서 작성 중 테스트와 컨테이너 진단은 재실행하지 않았다.
- 최종 자동 진단 증적은 저장소 루트 기준 `logs/day3-final.json`이다. 문서 작성 중 이 파일의 점검 ID와 판정 12건을 대조해 모두 PASS임을 확인했다.
- 수동 IDS 증적은 `lab/ids-waf-lab/artifacts/suricata-eve.json`과 `lab/ids-waf-lab/artifacts/suricata-fast.log`다. 두 파일에서 지정 SID를 대조했다. 증적 폴더는 Git에서 제외되며 이 문서에는 원본 JSON을 포함하지 않는다.

### 7. 구현 범위와 남은 작업

로컬 Docker 실습에서의 설정 진단과 제한된 동작 검증을 구현했다. 이 결과를 실제 기업 네트워크 운영 경험이나 운영 환경 전체의 보안 검증으로 확대할 수 없다. 실제 네트워크 실시간 수집, IPS 인라인 차단, 원격 자산 수집의 Scope 연동, 공식 기준 매핑, DB 기반 재점검 이력 및 PDF 보고서 통합은 이번 작업에서 구현하지 않았다.
