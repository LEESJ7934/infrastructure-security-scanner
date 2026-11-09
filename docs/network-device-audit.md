# Router 및 Switch 설정 진단 실습

## 현재 완료 범위와 환경 상태

환경 조사, 오프라인 진단 코드, 격리 구성 파일과 사용자 실행 절차까지 준비했다. **실제 컨테이너 생성·설치·보안 설정 변경·패킷 시험은 이번 작업에서 수행하지 않았다.** 합성 테스트의 FAIL→PASS는 실제 실습 결과가 아니다.

조사 결과: Docker CLI와 Compose **2.40.0-desktop.1**은 확인됐고 Compose 구성 문법 검증은 통과했다. Docker Desktop Linux 엔진 named pipe가 없어 서버 조회는 실패했다. WSL 조회는 E_ACCESSDENIED였으며 배포판/버전은 미확인이다. Hyper-V VM 상태 및 여유 메모리 조회는 CIM 접근 제한으로 미확인이다. 기존 OPNsense LAN/Windows LAB/WSL 가상 어댑터는 관찰했지만 변경하지 않았다. 호스트 포트 및 Docker 기존 서브넷 전체 충돌 검사는 미완료다. 조회 실패를 장비 종료나 메모리 여유로 추정하지 않는다.

## Windows 작업 보존

기존 Windows 공개 후보 14개 파일을 비밀정보 패턴 검사 및 staged 파일 검토 후 로컬 checkpoint로 보존했다. 실제 개인 증적/보고서와 상세 일지는 포함하지 않았다. 당시 상세 Windows 기록과 공개 요약본은 분리 관리했으나, 현재 공개된 상세 설명은 `docs/windows-server-audit.md`로 일원화했다. 이전 별도 요약 파일은 Git 이력에서 확인할 수 있다. 원본과 개인 자료의 명시적 파일 목록은 Git 외부 로컬 백업에서 SHA-256으로 대조했다. `.env`, 키, VM 이미지, 원본 설정 백업을 Git에 넣지 않았다. 원격 push/main 병합은 하지 않았다.

## 선택한 환경과 한계

Docker Desktop Linux backend + Compose를 우선 사용한다. 새 VM, Containerlab, 별도 Docker Engine 설치는 필요하지 않다. 기본은 **Alpine Linux kernel 라우팅**이며 FRR 패키지는 준비하지만 daemon을 자동 활성화하지 않는다. Alpine 3.22 이미지에 FRR/iproute2/nftables/Python을 빌드하여 Router와 두 Client가 이미지 레이어를 공유한다. Alpine 3.22의 FRR 패키지는 [공식 패키지 인덱스](https://pkgs.alpinelinux.org/packages?branch=v3.22&name=frr)에서 확인했다. 기본 모드 제품/버전은 linux_router/kernel이며 검토 후 별도 FRR 런타임을 사용하는 경우에만 linux_frr/실제 FRR 버전을 기록한다. 이미지 빌드는 인터넷 패키지 다운로드가 필요하지만, 실습 런타임은 내부 네트워크만 사용한다.

- 관리: 10.203.0.0/24, router mgmt0=.254. 관리 인터페이스에는 SSH를 자동 설치/개방하지 않는다. 기본 관리는 로컬 Docker exec/vtysh다.
- Data-A: 10.203.10.0/24, router data0=.254, Client-A=.10.
- Data-B: 10.203.20.0/24, router data1=.254, Client-B=.10.
- Client-A → data_a Linux bridge → Router IPv4 forwarding → data_b Linux bridge → Client-B.
- L2 확인은 Client-A와 같은 bridge의 Router data0 사이 ping/neighbor 조회로 수행한다.

모든 네트워크는 `internal:true`, 호스트 포트 publication/host network/호스트 볼륨 마운트는 없다. [Docker internal 네트워크](https://docs.docker.com/reference/compose-file/networks/)는 외부 연결을 제한하지만 Docker 관리자 권한 및 호스트 전체 보안을 증명하지 않는다. 기존 OPNsense 네트워크/컨테이너는 건드리지 않는다. 별도 브리지는 브로드캐스트 도메인 분리이며 **802.1Q VLAN filtering 검증이 아니다**.

컨테이너 메모리 제한 합계는 384MiB, CPU 제한 합계는 1 core다. Docker/WSL 자체 오버헤드는 별도다. 16GB 호스트에서 기존 VM 실행 상태를 확인하고 최소 4GiB 여유를 권장한다. 이는 실측 메모리 사용량이 아니다. 부족하면 사용자가 기존 작업을 안전하게 정리할지 판단하며 스크립트는 VM을 종료하지 않는다.

`interface_name` 사용을 위해 Compose 2.36 이상이 필요하다. 현재 확인한 CLI는 충족한다. [서비스 명세](https://docs.docker.com/reference/compose-file/services/)를 따른다. privileged/SYS_ADMIN/host network는 사용하지 않는다. 필요한 NET_ADMIN/NET_RAW 등 capability는 컨테이너 namespace에 한정한다.

**FRR 10.2의 [공식 zebra 소스](https://github.com/FRRouting/frr/blob/stable/10.2/zebra/main.c)는 SYS_ADMIN을 capability 목록에 포함한다.** 안전한 기본 프로파일은 이를 추가하거나 우회하지 않고 Linux routing만 수행한다. FRR 로그 점검 R05는 NOT_TESTED다. NETWORK_LAB_START_FRR=1은 추후 검토용 opt-in이며 현재 capability 집합에서 기동 실패할 수 있어 지금 켜도록 권장하지 않는다. 실패를 성공으로 표시하지 않으며 privileged/SYS_ADMIN 추가·cap 검사 우회·호스트 보안 완화는 자동으로 하지 않는다. FRR 실동작이 필수인 후속 단계에서 권한 범위와 대체 실행 방법을 먼저 별도 검토해야 한다. [FRR 기본 옵션](https://github.com/FRRouting/frr/blob/master/doc/manpages/common-options.rst) 및 [FRR 구성 설명](https://docs.frrouting.org/en/latest/setup.html)을 참고한다.

Containerlab은 이번 구성에 필요 없다. 추후 사용할 경우 [공식 Windows/WSL2 안내](https://containerlab.dev/windows/)의 Linux 런타임과 Docker 통합 조건을 검토한다. Docker Desktop 통합과 WSL 내부 별도 Docker Engine이 충돌할 수 있으므로 안내의 설치 명령을 무조건 실행하지 않는다.

## 내부 진단 항목 8개

공식 KISA 번호를 추정하지 않고 NET-LAB 내부 식별자를 사용한다. 모든 항목은 기존 AuditRule/Observation/evaluate/AuditStatus를 사용한다. LAB에서는 조직 승인이나 독립 기대 해시가 없다는 이유로 설정 판정을 막지 않는다.

| 항목 | 실제 수집·판정 범위 | 초기 플랫폼 한계 |
|---|---|---|
| R01 SSH 관리 | sshd 설치 여부, effective config의 root/password 로그인 및 관리 주소 바인딩 | 기본 이미지에 SSH 서버 없음 확인 시 NOT_APPLICABLE. SSH 접속 성공으로 주장하지 않음 |
| R02 Telnet 노출 | 실제 TCP listen 중 23 및 FRR VTY 2600~2619의 비-loopback 바인딩 | listener 구성 대조. 실제 외부 접근 시험과 분리 |
| R03 관리 접근 규칙 | inet/phase2_guard/input의 default drop과 루프백·established/related·IPv4 ICMP 예외 | 대상 chain의 미승인 ACCEPT는 FAIL, 기타 미해석 문장은 NEEDS_REVIEW. Docker NAT/다른 chain은 범위 밖이며 전체 호스트 정책 검증 아님 |
| R04 불필요 관리 서비스 | 이 LAB에 불필요한 80/443/8080/8443 비-loopback listener | 초기 demo HTTP 8080만 의도적으로 기동 |
| R05 로그 설정 | 실제 FRR running-config의 log stdout informational/debugging | 기본 Linux 모드에서 NOT_TESTED. FRR 런타임 확인 시에만 수집. 이벤트 전달 검증과 별도 |
| S01 관리 제한 | Docker bridge에는 독립 switch 관리 plane이 없음 | NOT_APPLICABLE. Docker daemon 접근통제는 이 항목 PASS로 대체하지 않음 |
| S02 VLAN 분리 | 802.1Q VLAN은 이 topology에 없음 | NOT_APPLICABLE. 별도 Docker network를 VLAN PASS로 오인하지 않음 |
| S03 불필요 가상 연결 | 각 bridge에 router와 해당 client만 정확히 연결되는지 | 가상 endpoint membership만 판정. 물리 포트 shutdown 상태 아님 |

수집 실패는 ERROR, 미수집은 NOT_TESTED, 필요한 필드/버전이 없거나 해석 범위가 불확실하면 NEEDS_REVIEW다. 현재 입력 플랫폼 밖 Cisco 전용 기능을 검증하지 않는다. 지원하는 범위를 정직하게 좁혀 8개 슬롯을 정의했으며 8개 모두 PASS를 목표로 하지 않는다.

## 사용자 실행 단계 (아직 실행하지 않음)

### 1. 읽기 전용 준비 확인

```powershell
Set-Location C:\Projects\infrastructure-security-scanner-clone
.\scripts\check_network_lab.ps1
docker compose -f .\lab\network-device-lab\compose.json config --quiet
.\.venv\Scripts\python.exe -B -m scripts.run_network_audit
```

기본 실행은 네트워크 호출 없이 8개 NOT_TESTED다. Linux 엔진이 안 켜져 있으면 기존 Docker Desktop을 사용자가 열고 Linux containers/WSL2 backend를 확인한다. `wsl --list --verbose`, Hyper-V Manager, Task Manager를 사용자 콘솔에서 확인한다. 새 프로그램 설치나 호스트 네트워크 변경은 필요 여부를 확인한 뒤 **별도 작업**으로 판단한다. 이번 코드가 자동 설치/시작하지 않는다.

기존 호스트/Docker subnet과 10.203.* 세 대역이 겹치면 기동하지 않는다. Compose, nft 파일, start.py의 route, collect.py의 management 주소를 함께 일관되게 바꾼 뒤 다시 검토한다. 다른 실습 네트워크를 삭제/재주소화하지 않는다. 호스트 포트는 쓰지 않아 22/443/8080 서비스가 있어도 이를 중지할 필요가 없다.

### 2. 새 LAB 자원만 빌드·기동 (사용자가 수행)

```powershell
docker compose -f .\lab\network-device-lab\compose.json build router
docker compose -f .\lab\network-device-lab\compose.json up -d --no-build
docker compose -f .\lab\network-device-lab\compose.json ps
docker compose -f .\lab\network-device-lab\compose.json logs --tail 40 router
docker compose -f .\lab\network-device-lab\compose.json exec -T router ip -Version
docker compose -f .\lab\network-device-lab\compose.json exec -T router ip route show
```

이 단계는 이미지 패키지 설치, **새 Docker 내부 bridge/컨테이너 생성**, 해당 컨테이너의 route/nft 설정을 수행한다. 호스트나 기존 VM의 방화벽/라우팅을 바꾸지 않는다. 빌드/FRR 기동 실패는 실제 오류로 남기고 다음 단계 PASS를 만들지 않는다. 이미지를 검토 후 digest 고정하는 추가 재현성 작업은 가능하지만, 현재 이미지를 검증 완료로 표시하지 않는다.

### 3. 실제 before 수집

```powershell
New-Item -ItemType Directory -Force .\logs\phase2-network | Out-Null
.\.venv\Scripts\python.exe -B -m scripts.run_network_audit --execute `
  --output .\logs\phase2-network\before.json
```

`--execute`는 로컬 default/desktop-linux context만 허용하고 Linux 엔진·Compose 소유 라벨·기동 상태·권한·마운트·포트 정책을 확인한다. 고정된 3개 컨테이너/2개 network만 조회하며 router의 고정 수집 프로그램을 실행한다. SSH/실장비 API는 사용하지 않는다. raw config, Docker Env, 인증정보, 원본 running-config를 보고서로 출력하지 않는다. 각 API 실패는 성공으로 바꾸지 않는다.

**예상 목표(미실행):** input policy accept로 R03 FAIL, data 8080 listener로 R04 FAIL. R02/S03은 실제 값에 따라 평가하고 R05는 FRR 미기동으로 NOT_TESTED다. 이는 예상이며 현재 실장비 진단 결과가 아니다.

### 4. 별도 패킷 증적 (선택, 사용자 수행)

```powershell
# L2 adjacency / routing / 현재 demo HTTP: LAB 주소만 지정한다.
docker compose -f .\lab\network-device-lab\compose.json exec -T client-a ping -c 3 10.203.10.254
docker compose -f .\lab\network-device-lab\compose.json exec -T client-a ip neigh show dev data0
docker compose -f .\lab\network-device-lab\compose.json exec -T client-a ip route get 10.203.20.10
docker compose -f .\lab\network-device-lab\compose.json exec -T client-a ping -c 3 10.203.20.10
docker compose -f .\lab\network-device-lab\compose.json exec -T client-a wget -T 2 -O - http://10.203.10.254:8080
```

실제 출력은 별도의 logs/phase2-network/packet-before.txt 등에 저장하고 명령·시각·실제 성공/실패를 기록한다. 진단 JSON의 packet_verification은 자동으로 PASS로 바뀌지 않으며 수집만 했는데 트래픽을 시험했다고 표시하지 않는다.

### 5. 명시적 컨테이너 설정 개선과 재조회

```powershell
# 승인 범위: 새 LAB router 내부의 demo HTTP와 phase2_guard만 변경한다.
docker compose -f .\lab\network-device-lab\compose.json exec -T router python3 /opt/network-lab/harden.py --apply
.\.venv\Scripts\python.exe -B -m scripts.run_network_audit --execute `
  --output .\logs\phase2-network\after.json

# 기존 저장본의 오프라인 재평가도 가능하다. Docker 불필요.
.\.venv\Scripts\python.exe -B -m scripts.run_network_audit `
  --input-json .\logs\phase2-network\after.json
```

harden.py는 global flush를 하지 않고 소유 nft table만 교체하며, PID/명령을 대조한 LAB demo만 중지한다. 개선 프로그램은 수집기와 분리돼 있고 `--apply`가 없으면 실행하지 않는다. 개선 프로그램 메시지만으로 PASS를 인정하지 말고 실제 R03/R04 재조회 결과를 확인한다. 이후 위 ping/HTTP 명령을 다시 수행하면 HTTP 실패와 L3 통신 유지 여부를 별도 검증할 수 있다.

재시작하면 entrypoint가 초기 before 조건을 다시 구성한다. before/after 파일은 덮어쓰지 않으며 원상복구·반복 실습 시 새 파일명을 사용한다. 사용 후 정리가 필요하면 **이 Compose 파일의 프로젝트만** `docker compose -f .\lab\network-device-lab\compose.json down`으로 정리한다. docker system/network prune이나 기존 컨테이너/VM 조작은 하지 않는다.

## 테스트와 보고서 연동

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_network_audit
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
```

단위 테스트는 합성 설정과 mocked Docker만 사용한다. `--synthetic`을 명시해야 합성 JSON을 평가하며 `synthetic_results`에만 출력한다. 실제 `results`와 섞지 않는다. `to_report_snapshot()`은 기존 ReportResult/SourceSnapshot을 재사용하며 day=0은 Phase2 소스 표식이다. 기존 Day5 입력 목록/증적 allowlist를 자동 확장하거나 기존 보고서를 수정하지 않는다.

현재 미검증: Docker Linux 엔진 및 WSL 배포판 실제 가용성, VM 상태/여유 RAM, 전체 subnet 충돌, FRR capability 호환성과 기동, 실제 수집 구조/명령, 실제 FAIL→PASS, L2/L3 패킷 동작, 로그 전달. 완료 기준은 정상 기동 → 실제 수집 → R03/R04 FAIL 확인 → LAB 내부 개선 → 실제 재수집 PASS → 서로 다른 JSON 저장이며 패킷 증거는 별도로 남기는 것이다.

## R03 JSON 표현 호환성 수정과 실제 LAB 재점검

사용자가 Router/Client 정상 실행과 R04 FAIL→PASS를 실제 확인했다. 최초 before.json의 R03은 FAIL, 기존 after.json의 R03은 NEEDS_REVIEW였고 두 파일의 원본은 그대로 보존했다. 앞 절의 초기 미검증 목록은 초기 구현 시점 기록이며 이번 사용자 실습 확인과 구분한다.

**정확한 인식 실패 원인:** 사용자가 새로 내보낸 logs/phase2-network/guard-input.json의 conntrack 조건은 아래 형태였다.

```json
{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}}
```

기존 파서는 right가 `{"set":["established","related"]}`인 경우만 허용했다. 배열 표현은 의미가 같지만 전체 dict 비교에 걸려 recognized_scope_only=false가 됐다. 루프백/ICMP 조건은 기존에도 인식 가능한 형태였고, 이번에 확인한 원인을 Docker NAT 때문이라고 추정하지 않았다.

수정 내용:

- 배열과 set wrapper, 집합 원소 순서 차이를 같은 의미로 정규화한다. `new` 상태나 부정 비교는 허용 예외로 확대하지 않는다.
- IPv4 ICMP 문자열/프로토콜 번호 1을 지원한다. TCP/ICMPv6/잘못된 bool은 허용하지 않는다.
- counter는 match/verdict를 바꾸지 않는 부가 정보로 처리한다. 알 수 없는 문장/추가 match/jump는 무시하지 않는다.
- 실제 조회를 `nft -j list chain inet phase2_guard input`으로 제한한다. Docker NAT/다른 테이블의 체인을 소유 input 정책으로 세지 않는다. 전체 유효 ruleset의 안전성을 주장하지 않는다.
- 추가 ACCEPT가 있으면 disallowed_accept=true로 FAIL을 유지한다. 다른 미해석 문장, 잘못된/중복된 chain metadata는 PASS로 만들지 않는다.
- 진단 결과에 parser_version/query_scope/인식 예외/미인식 이유를 포함한다. R03 규칙은 NET-LAB-0.2, 나머지 규칙은 0.1이다. 기존 R03의 동일 LAB 기준을 표현 정규화로 수정한 버전 관계만 비교에 명시적으로 허용한다.

실행 중 이미지에는 구형 collect.py가 들어 있을 수 있다. 새 host 수집기는 소유·격리 조건을 확인한 뒤 별도의 읽기 전용 nft chain 조회를 수행하고 **호스트의 최신 파서**를 사용한다. 수정을 반영하려고 컨테이너를 rebuild/up/restart/cp하거나 방화벽 규칙을 다시 적용할 필요가 없다. 기존 after 설정을 초기 before 상태로 되돌리는 작업도 하지 않는다.

### 이번 after-v2.json 생성 방식

Codex의 Docker Linux 엔진 조회는 실패했다. 따라서 사용자가 정상 PowerShell에서 실행한 다음 명령의 실제 JSON을 읽었다.

```powershell
docker compose -f .\lab\network-device-lab\compose.json exec -T router `
  nft -j list chain inet phase2_guard input |
  Out-File -Encoding utf8 -NoClobber .\logs\phase2-network\guard-input.json
```

원본 chain은 policy=drop, 허용 예외 3종뿐이었다. 다음 **오프라인 R03 재점검**으로 logs/phase2-network/after-v2.json을 새로 생성했다.

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_network_audit `
  --input-json .\logs\phase2-network\after.json `
  --guard-json .\logs\phase2-network\guard-input.json `
  --baseline-json .\logs\phase2-network\before.json `
  --output .\logs\phase2-network\after-v2.json
```

결과: R03 PASS / R04 PASS, baseline 비교에 R03·R04 FAIL→PASS(IMPROVED_OBSERVED) 2건을 연결했다. R03은 새 사용자 export의 재분석, R04 등 다른 항목은 기존 after JSON의 값 재사용이다. R03 수집 시각은 export에 없어 null로 보존하고 파일 mtime을 수집 시각으로 만들지 않았다. checked_at/reanalysis_at은 재분석 시각이다. 다른 항목을 이번에 직접 live 재수집했다고 표시하지 않는다. 해당 한계는 mode=LAB_OFFLINE_GUARD_RETEST와 supplemental_guard_evidence에 기록한다. 패킷 검증과 전체 정책 검증은 별도다.

after-v2.json은 이미 생성되어 있으므로 위 명령을 그대로 반복하면 덮어쓰기 오류가 난다. 실제 사용자 콘솔에서 모든 항목을 새로 읽으려면 다음처럼 **다른 새 파일명**을 사용한다. 이번 작업은 규칙 변경 명령을 포함하지 않는다.

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_network_audit --execute `
  --baseline-json .\logs\phase2-network\before.json `
  --output .\logs\phase2-network\after-live-v3.json

.\.venv\Scripts\python.exe -B -m unittest tests.test_network_audit tests.test_network_guard
```

baseline 결과는 저장된 원래 판정을 읽고 덮어쓰지 않는다. 중복 항목을 임의 선택하지 않고 자산/플랫폼/버전/범위/규칙 관계가 다르면 직접 비교하지 않는다. 이 LAB 비교는 관찰된 상태 변화이며, 이번 코드 실행이 방화벽 조치를 수행했다는 뜻이 아니다. before/after 원본은 해시 대조로 변경 없음을 확인했다.
