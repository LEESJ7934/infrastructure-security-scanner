# Suricata IPS 전용 LAB

## 현재 결과: 인라인 차단 미완료

2026-11-07 KST 실습에서 Suricata 8.0.6 바이너리의 NFQueue 지원과
alert/drop 두 규칙의 `suricata -T --init-errors-fatal` 문법 검사는 확인했다.
그러나 Docker Desktop Linux 커널의 새 네임스페이스에서 `nft add rule inet
p2ips_kernel_probe probe queue num 0`이 `No such file or directory`로 실패했다.
이는 이 환경의 nftables queue 기능을 사용할 수 없다는 직접 증거이며,
커널 모듈의 설치 여부·비활성화 이유까지 확정한 것은 아니다.
바이너리 빌드 지원과 커널 실행 지원을 구분한다.
호스트 모듈 적재, SYS_MODULE/SYS_ADMIN, privileged, 전역 방화벽 변경은 하지 않았다.
실제 정상 HTTP 허용, alert 전달, drop 차단 및 개선 관찰은 모두 미검증이다.
EVE/PCAP 파일을 만들거나 차단 성공을 주장하지 않는다.

## 기존 구성과 선택 근거

- `lab/day3/compose.yaml`: Suricata 8.0.6, PCAP 오프라인 IDS 재생,
  network_mode none. 기존 IDS 코드·규칙·증적을 변경하지 않았다.
- `config_audit/collectors/suricata.py`, `scripts/run_day3_audit.py`:
  기존 공통 엔진 및 IDS 설정/이벤트 분석은 그대로 유지한다.
- OPNsense는 기존 Hyper-V 관리망을 보존한다. Netmap/Divert의 제품 지원과
  현재 VM/NIC의 사용 가능성은 다르므로 이번에 OPNsense IPS를 검증하지 않았다.
- 별도 Linux NFQUEUE 라우터를 선택했다. 일반 Docker 내부 bridge 두 개 사이의
  라우팅 실패 이력이 있어 단일 internal /16 fabric 안에서 각 노드의 /24 경로를
  설정하고 TTL 변화, PCAP 및 nft queue 카운터로 라우터 경유를 검증하도록 했다.

## 목표 패킷 경로 (구현 설계, 실제 전달 미검증)

```text
Client 10.207.10.10/24
  -> gateway 10.207.10.254 / 10.207.20.254
     nft forward queue 0 <-> Suricata 8.0.6 NFQUEUE
  -> HTTP server 10.207.20.10/24:8080
응답은 gateway를 통해 역방향 검사
```

프로젝트 scanner-p2ips, internal bridge scanner-p2ips_fabric만 사용한다.
노드의 기본 경로와 redirects를 제거/비활성화하고, 외부 연결·호스트 포트·bind mount를
금지한다. sensor는 새 gateway 네트워크 네임스페이스만 공유한다.
NET_ADMIN/NET_RAW만 부여하고 read-only rootfs, tmpfs, no-new-privileges를 사용한다.
호스트나 기존 LAB 네임스페이스에는 규칙을 쓰지 않는다.
Suricata 체크섬 검사는 가상 NIC 오프로딩 실습에 한해 비활성화했으며 운영 권고가 아니다.

## 시험과 판정

내부 LAB 기준이며 KISA 공식 인증 기준이 아니다.

| 시험 | 기대 동작 | 필수 증거 |
|---|---|---|
| 정상 /control | ALLOWED | HTTP 응답, 서버 수신, 양방향 PCAP·TTL 경유 |
| before /ips-lab-marker | ALERTED_NOT_BLOCKED | SID 1000701 rev1 allowed 탐지 및 실제 전달 |
| after 동일 URI | BLOCKED_CONFIRMED | SID 1000701 rev2 blocked, gateway 유입, 이후 전달 없음, 서버 수신 없음, 양옆 정상 요청 성공 |

각 요청은 실행 ID 및 TCP 출발지 포트로 연결한다. 전후 같은 URI를 사용한다.
현재 프로세스·큐 바인딩·규칙·EVE 시각/5-tuple·서버 이벤트·세 지점 PCAP와
커널 캡처 손실 0을 모두 확인한다. 로그 하나, timeout 하나, 경로 불명확,
미실행 프로세스 또는 누락/변조 증적은 차단 확정의 근거가 아니다.
기존 evaluate()로 IPS-LAB-001~004를 평가한다. 실패 배포는 IPS-LAB-000 ERROR,
패킷 항목은 NOT_TESTED로 보고한다. alert-only 정책의 전달은 정상 IDS 동작이다.
IMPROVED_OBSERVED는 의도된 차단 정책이 실제로 추가 검증된 경우에만 기록한다.

## 실행

프로젝트 루트 PowerShell에서 기본 모드는 Docker에 접근하지 않는다.

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_suricata_ips
.\.venv\Scripts\python.exe -B -m unittest tests.test_suricata_ips
```

현재 Docker 커널에서는 재실행해도 차단 시험을 완료할 수 없다.
NFQUEUE 사용이 확인된 별도 Linux 환경을 마련하는 것이 다음 조건이다.
본 실행기는 현재 로컬 Docker Desktop named pipe로 고정되어 있다.
별도 Linux 엔진을 사용하려면 명시적인 엔진 선택·소유권·범위 검사를 먼저
포팅해야 하며 DOCKER_HOST 변경만으로 우회할 수 없다.
호스트 방화벽/커널 변경은 본 실행 범위가 아니다.

지원 조건을 만족한 동일 Docker Desktop 환경에서만 다음 명령으로 새 실행을 한다.
기존 이미지 scanner-p2net:local 및 jasonish/suricata:8.0.6이 필요하다.

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_suricata_ips --execute
```

실행기는 고유 reports/phase2-suricata-ips/<UTC>-<UUID>에 저장하고 기존 파일을
덮어쓰지 않는다. 기존 동명 LAB/CIDR 충돌, 외부 엔드포인트, 이미지·권한·마운트
불일치를 거부한다. 성공/실패 후 이번 LAB만 정리한다. 삭제 전 이름·라벨·ID를
확인하고 외부 엔드포인트가 있으면 중단한다. 중단된 gateway도 정리한다.
컨테이너 제거로 새 네임스페이스의 라우팅/규칙이 폐기되며 기존 환경은 보존한다.
공유된 Docker 네트워크 이름은 순서가 아닌 집합으로 비교한다.

완전한 성공 번들만 아래 오프라인 재분석 경로에 넣는다. 실패 보고서는 JSON/PDF를
직접 읽으며, 누락된 성공 번들을 생성하지 않는다.

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_suricata_ips --evidence-dir .\reports\phase2-suricata-ips\<완전한-실행-ID>
```

## 보고서·증적 및 종료 조건

성공 시 bundle.json, manifest.json, before/after phase.json, EVE, 세 PCAP,
캡처 메타데이터, JSON/PDF, 정책 비교를 생성한다. 실패 시 실제 오류와 수집한
능력/문법 검사만 보존한다. manifest SHA-256은 현재 파일 무결성 검사이며 독립적인
출처 진위 인증이 아니다. 수집 시각과 보고서 재분석 시각은 구분한다.

완료 조건은 실제 정상 요청 성공, alert 탐지 및 전달, drop 실제 차단,
동일 범위 정책 개선 관찰, 전체 증적 해시 일치, 임시 LAB 정리 확인이다.
현재는 커널 queue 기능 부족으로 이 조건을 충족하지 못했다.
AWS, 기존 VM, IDS/WAF, OPNsense 및 다른 Docker LAB에는 변경을 수행하지 않았다.

## 공식 참고

- https://docs.suricata.io/en/latest/ips/setting-up-ipsinline-for-linux.html
- https://docs.suricata.io/en/suricata-8.0.1/ips/ips-concept.html
- https://docs.opnsense.org/manual/ips.html
