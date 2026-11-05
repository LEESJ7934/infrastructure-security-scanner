# 3일차 개발 결과

## 1. 실습 목표와 구성

Suricata IDS의 유효 설정과 오프라인 탐지, ModSecurity WAF의 유효 설정과 내부 HTTP 정책 차단을 검증하고, 결과를 기존 `config_audit` 판정 엔진에 연결했다.

실습 프로젝트는 `infra-day3-lab`이다. Suricata는 `jasonish/suricata:8.0.6` 이미지에서 `suricata` 사용자로 실행한다. WAF는 `owasp/modsecurity-crs:4.25.2-nginx-202610180210-lts` 이미지를 사용한다. Suricata에는 네트워크를 연결하지 않으며, WAF·테스트 백엔드·클라이언트는 실습 전용 내부 네트워크를 사용한다. 호스트 포트를 공개하지 않고 기존 Day 2 및 DB 네트워크와 분리했다.

| 신규 파일 | 실제 구현 내용 |
|---|---|
| [config_audit/collectors/suricata.py](../../config_audit/collectors/suricata.py) | 유효 EVE 설정과 `HOME_NET`, 규칙 로드 집계, EVE의 SID 및 패킷 번호를 해석한다. |
| [config_audit/collectors/modsecurity.py](../../config_audit/collectors/modsecurity.py) | Include 구조, 렌더링된 설정, CRS 임계값과 로드 기록을 확인하고 요청 ID로 감사 이벤트를 대조한다. |
| [scripts/run_day3_audit.py](../../scripts/run_day3_audit.py) | `--execute` 승인 후 로컬 실습 대상을 검증하고 증적을 수집한다. 12개 관찰값을 기존 `evaluate()`로 평가해 JSON을 출력한다. |
| [tests/test_day3_audit.py](../../tests/test_day3_audit.py) | Docker subprocess를 모의 처리하는 테스트 22개를 포함한다. 최초 14개에 Include Chain 회귀 테스트 8개를 추가했다. |
| [lab/day3/](../../lab/day3/) | Compose 환경, 합성 PCAP 생성기와 로컬 규칙, 고정 응답 백엔드와 내부 요청 클라이언트, 실행 안내 및 산출물 제외 규칙을 포함한다. |

## 2. Suricata IDS 설정과 탐지 검증

생성기는 정상 대조군과 실습 문자열을 담은 UDP 패킷을 각각 한 개씩 합성 PCAP에 기록한다. 자동 실행기는 PCAP 해시와 로컬 규칙 SID를 확인하고, 매 실행마다 새 네트워크 차단 컨테이너에서 `--dump-config`, `-T`, 오프라인 재생을 수행한다. 재생은 설정 검사를 통과했을 때 진행하며 이번 실행에서 생성한 `/tmp/eve.json`을 읽는다. 합성 패킷의 2023년 시각과 진단 결과의 UTC `checked_at`은 별도로 기록된다.

수동 실습의 EVE 증적에는 이벤트 3건과 경보 1건이 있다. 경보는 두 번째 패킷의 SID `1000003`이며, Fast 로그에서도 같은 SID를 확인했다. SID `1000003`과 서명 `DAY3 LAB synthetic marker`는 합성 입력의 실습용 규칙이다. 이 결과는 IDS의 오프라인 탐지 검증이며, 트래픽을 경유시켜 막는 IPS 인라인 차단은 검증하지 않았다.

## 3. ModSecurity WAF 설정과 차단 검증

자동 실행기는 WAF와 백엔드의 프로젝트·서비스 라벨, 내부 네트워크, 호스트 포트 미공개 및 프록시 대상을 확인한다. `nginx -T`와 실제 포함된 ModSecurity·CRS 설정을 읽고, 환경변수 선언만으로 통과를 판정하지 않는다.

사용자가 수행한 Docker 실습에서 정상 GET은 HTTP 200과 백엔드 표식을 반환했고, 정책상 허용되지 않는 PUT은 HTTP 403을 반환했다. 같은 요청의 JSON 감사 이벤트에서 허용되지 않은 메서드를 탐지한 `911100`과 인바운드 이상 점수에 따른 차단 규칙 `949110`을 확인했다. 자동 실행기도 고유 요청 ID, HTTP 응답, 두 규칙의 감사 기록을 함께 요구한다. 검증 범위는 내부 메서드 정책 차단이다. 전체 웹 취약점 진단, 요청 본문 기반 공격 탐지, 실제 공격 대응 성능은 검증하지 않았다.

## 4. 12개 실습 점검 결과

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

## 5. Include Chain 오류와 수정

최초 자동 진단에서 IDS 6개는 통과했지만 WAF 6개는 `include_chain_unverified`로 `NEEDS_REVIEW`가 됐다. 기존 검증기는 필수 Include 4개와 정확히 일치하는 구성만 허용했다. 실제 이미지에서는 공식 플러그인의 `config`, `before`, `after` Include가 활성화되어 7개였다.

필수 경로 4개를 유지하고 공식 플러그인 glob을 지정된 위치에서만 허용하도록 수정했다. `config`와 `before`는 CRS 규칙 앞, `after`는 뒤에 있어야 한다. 필수 경로 누락, 임의 경로, 중복, 순서 위반 및 예상 밖 중첩 Include는 거부한다. 플러그인 Include가 비활성화된 구성은 허용하며, 실제 로드 오류는 `nginx -T` 실패로 구분한다. Include 검증을 통과한 뒤에도 유효 설정, CRS 로드 기록, HTTP·감사 증적을 별도로 확인한다.

## 6. 테스트와 증적

- 사용자가 Windows PowerShell에서 **전체 381개 단위 테스트 통과**를 최종 확인했다. 기존 359개에는 앞선 프로젝트 기능의 단위 테스트가 포함되며, Day 3에서 추가한 테스트는 22개다.
- 앞선 Codex 실행에서는 Day 3 테스트 22개가 통과했다. 전체 실행은 Git Bash 초기화와 로컬 루프백 연결 제한으로 기존 테스트 5개가 실패했다. 문서 작성 중 테스트와 컨테이너 진단은 재실행하지 않았다.
- 최종 자동 진단 증적은 저장소 루트 기준 `logs/day3-final.json`이다. 문서 작성 중 이 파일의 점검 ID와 판정 12건을 대조해 모두 PASS임을 확인했다.
- 수동 IDS 증적은 `lab/day3/artifacts/suricata-eve.json`과 `lab/day3/artifacts/suricata-fast.log`다. 두 파일에서 지정 SID를 대조했다. 증적 폴더는 Git에서 제외되며 이 문서에는 원본 JSON을 포함하지 않는다.

## 7. 구현 범위와 남은 작업

로컬 Docker 실습에서의 설정 진단과 제한된 동작 검증을 구현했다. 이 결과를 실제 기업 네트워크 운영 경험이나 운영 환경 전체의 보안 검증으로 확대할 수 없다. 실제 네트워크 실시간 수집, IPS 인라인 차단, 원격 자산 수집의 Scope 연동, 공식 기준 매핑, DB 기반 재점검 이력 및 PDF 보고서 통합은 이번 작업에서 구현하지 않았다.

## 8. 4일차 계획

1. OPNsense VM과 테스트 클라이언트를 외부 운영망에서 분리한 실습 네트워크에 구성한다.
2. 승인된 인터페이스·주소·방화벽 규칙·관리 접근 범위를 정하고, 설정과 로그를 읽기 전용으로 확인할 항목을 선정한다.
3. 같은 테스트 경로에서 허용·차단 정책을 비교하고 응답 및 방화벽 로그를 대조한다.
4. 확인한 설정과 동작 증거를 분리해 기록하고 공통 판정 엔진에 연결할 범위를 정한다.
