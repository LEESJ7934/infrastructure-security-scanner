# Router 경유 패킷 통신 검증

설정 진단 R03/R04와 패킷 검증은 별개 결과로 유지한다. 기존 `scanner-p2net` 설정이나 before/after 증적을 수정하지 않았다. 실제 Docker 명령은 사용자 PowerShell에서 실행했고, 저장된 JSON을 오프라인으로 재검증했다.

## 기존 토폴로지의 관찰

`logs/phase2-network/packet-existing.json`은 양방향 3개 전송, 0개 수신이다. 각 Client 송신 헤더는 3개지만 Router 수신 헤더는 0개다. 경로는 각각 Router .254를 선택했고 이웃 MAC도 해당 Router 인터페이스와 일치한다. Router ip_forward=1, 프로젝트 FORWARD 체인은 default drop 및 정확한 양방향 허용 규칙으로 확인됐다.

따라서 최초 관측 누락 지점은 Client 송신과 Router 수신 사이이다. 서로 다른 internal /24 bridge에서 원격 /24 목적지 패킷이 Docker 격리 필터에 걸렸을 가능성이 높다. Docker 호스트의 실제 DROP 규칙과 카운터는 수집하지 않았으므로 특정 호스트 규칙이 원인이라고 확정하지 않는다. 공식 internal 네트워크 설명: https://docs.docker.com/reference/cli/docker/network/create/#network-internal-mode---internal

## 별도 LAB과 실제 성공 결과

새 Compose 프로젝트 `scanner-p2pkt`만 구성했다. 단일 internal bridge의 Docker IPAM은 10.204.0.0/16이며 컨테이너 내부 주소는 다음과 같다.

| 노드 | 실제 인터페이스 주소 | 상대 서브넷 경로 |
|---|---|---|
| Client-A | 10.204.10.10/24 | via 10.204.10.254 |
| Router data0 | 10.204.10.254/24, 10.204.20.254/24 | 직접 연결 |
| Client-B | 10.204.20.10/24 | via 10.204.20.254 |

기본 경로와 published port는 없다. privileged, host network, 호스트 마운트를 사용하지 않는다. NET_ADMIN/NET_RAW는 이 LAB 네임스페이스에만 부여한다. 이미지 기반은 기존 로컬 scanner-p2net:local이며 별도 프로그램 설치나 Docker Engine 추가 설치는 없다.

공유 L2이므로 VLAN 분리나 악의적인 Client의 우회 방지를 검증한 구조는 아니다. 설정된 경로에 따른 이번 ICMP가 Router를 통과했다는 범위만 입증한다. Router FORWARD는 data0→data0 양방향 /24 허용 및 기본 drop이다. Client FORWARD도 기본 drop이다. 초기화는 새 컨테이너 내부 주소/경로/nft만 설정하며, 패킷 수집기는 설정을 변경하지 않는다.

`logs/phase2-network/packet-fabric.json`의 실제 결과:

- A→B: 3/3 수신, 손실 0%.
- B→A: 3/3 수신, 손실 0%.
- 양방향 각 8개 관측 단계에서 헤더 3개씩 확인.
- 요청과 응답 모두 Router 입구 TTL 64 → 출구 TTL 63, ICMP ID/sequence 대조.
- 실제 선택 경로, ip_forward=1, 프로젝트 FORWARD 체인 검증 성공.
- 기존 after-v3-live.json의 R03/R04 PASS는 원본 해시와 함께 참조하며 새 LAB의 설정 진단으로 재해석하지 않는다.

첫 기동의 Client-A는 redirect 검증 실패로 안전하게 종료했다. 인터페이스별 redirect/forwarding을 Docker endpoint sysctl로 명시하고 Client 전역 ip_forward 재설정을 제거한 뒤 사용자 재생성에서 정상 기동과 패킷 PASS를 확인했다. 호스트 sysctl, Docker 전역 방화벽, daemon은 변경하지 않았다. 관련 공식 옵션: https://docs.docker.com/reference/cli/docker/network/connect/

## 실행 명령 (프로젝트 루트 PowerShell)

이미 성공 증적이 있으므로 다시 실행할 필요는 없다. 재현 시 기존 증적을 덮어쓰지 않도록 출력 이름을 새로 정한다.

```powershell
docker compose -f .\lab\network-packet-lab\compose.json build router
docker compose -f .\lab\network-packet-lab\compose.json up -d --no-build
docker compose -f .\lab\network-packet-lab\compose.json ps
.\.venv\Scripts\python.exe -B -m scripts.run_network_packets --profile fabric --execute --config-evidence .\logs\phase2-network\after-v3-live.json --output .\logs\phase2-network\packet-fabric-retest.json
```

기본 실행은 네트워크 접근 없이 NOT_TESTED이다. `--execute`에서만 고정 프로젝트와 주소를 검사한 뒤 숫자 IP로 3개씩 Ping한다. 외부 Docker context, 다른 프로젝트/네트워크, 중지 컨테이너, 위험한 실행 범위는 거부한다. 기존 출력 파일은 덮어쓰지 않는다. 패킷 payload는 저장하지 않으며 ICMP 헤더와 LAB 설정 메타데이터만 기록한다.

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_network_packets tests.test_network_audit tests.test_network_guard
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
```

새 LAB만 종료할 경우 `docker compose -f .\lab\network-packet-lab\compose.json down`을 사용한다. 기존 phase2-network Compose 및 Docker 전역 설정을 조작할 필요가 없다.

## 증적과 한계

- 기존 실패: SHA-256 `1c5c3e8c4f8acbbd237aa8b5cef5e5fe12b8f14281c4937399d04cbe6242ddc2`
- 새 LAB 성공: SHA-256 `a7b2f203605d9ee195b5322393dec2c7f5e0c29beb5ee173fa5931f11a474424`
- 두 결과는 서로 다른 토폴로지이다. 같은 자산의 엄격한 조치 전후 비교로 표시하지 않는다.
- 해시는 현재 파일 식별 및 보존 확인이며 수집 출처의 진위 증명이 아니다.
- 원본 JSON의 checked_at을 보존한다. 오프라인 재분석을 새로운 실장비 시험으로 표시하지 않는다.
- 실제 L2 스위치 보안, VLAN, Cisco 기능, Docker 호스트 DROP 카운터는 검증하지 않았다.
