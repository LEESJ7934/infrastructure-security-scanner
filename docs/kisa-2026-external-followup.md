# 자동 수집과 남은 3개 항목 마감 절차

현재 **PASS 13/16(81.25%), NEEDS_REVIEW 3개(S-06/S-07/CA-09)**다. 모든 실행 명령을 사용자가 일일이 입력하도록 넘기지 않고, Docker는 이미 Actions에서 실제 수행했고 AWS/OPNsense도 현재 접근 가능한 범위에서 직접 읽었다. 아래는 남은 환경/운영 조건이 준비된 후 반복 가능한 단일 실행 경로다.

## 이미 자동 실측한 WEB/MySQL

[워크플로](../.github/workflows/kisa-web-mysql-live.yml)는 PR 변경 또는 workflow_dispatch로 일회용 두 job을 실행한다. 기존 엔진과 LAB 초기화·개선 코드를 재사용한다.

| 그룹 | 실제 수집 | 개선과 재점검 | 최종 확인 실행 |
|---|---|---|---|
| WEB-04/07/16 | Nginx/Tomcat 설정, 모든 선정 배포 루트 파일 목록, 정상/오류/목록/백업/docs/examples HTTP 응답 | 취약 단계→불필요 파일 제거·리스팅/정보 노출 제한 단계 재구성, 같은 제품·버전에서 다시 HTTP | [42586652707](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/42586652707), FAIL 3→PASS 3 |
| D-02/04/10 | 전체 계정, 정적/동적 관리자 권한, 역할·프록시 상속, 실제 두 출발지 TCP와 허용 SELECT, 전체 nft JSON | 계정·권한·Host 제한 및 해당 네임스페이스 ingress 제한, 같은 서버에서 SQL/네트워크 재수집 | 같은 실행, FAIL 3→PASS 3 |

MySQL gate의 NET_ADMIN은 해당 컨테이너 네임스페이스에만 있으며 호스트 정책을 바꾸지 않는다. 모든 네트워크는 internal이고 호스트에 포트를 공개하지 않는다. 비밀번호는 일회용 생성 후 메모리/표준 입력으로만 전달하며 원시 SQL 증거에 포함하지 않는다. 단위 테스트는 SYNTHETIC이며 VERIFIED_LAB 실적에 더하지 않는다.

## 기존 외부 LAB을 한 번에 다시 읽기

최신 프로젝트 루트에서 다음 하나의 명령을 사용한다. 기존 `.venv`, 독립 LAB export scope, 다운로드한 기존 CA, 기존 `key/OPNsense*.txt` 하나를 자동으로 찾는다. 모호하면 명시 경로를 요구하며, 새 키나 AWS 자원을 만들지 않는다.

```powershell
.\scripts\run_kisa_remaining_local.ps1
```

이 실행은 AWS/OPNsense의 **읽기 전용 증거 수집**이며, 전체 항목이 PASS가 된다는 뜻이 아니다. 원시는 새 `logs/kisa-remaining-<시각>/` 아래에 저장한다. API 403, 로그인 만료, 누락된 승인 scope/CA를 숨기지 않는다. 실제 key/Secret 값은 출력하거나 Git에 저장하지 않는다. 표준 AWS 로그인 만료는 `LoginRefreshRequired`로 분류하며, 수집 전에 기존 CLI 세션 갱신이 필요하다.

자동 발견을 사용할 수 없으면 명시한 기존 로컬 경로만 사용한다.

```powershell
.\scripts\run_kisa_remaining_local.ps1 `
  -AwsScopePath '<기존_독립_LAB_scope.json>' `
  -CaBundlePath '<기존_LAB_CA.pem>' `
  -ApiKeyFile '<기존_key_secret_TXT>' `
  -ApiAccount 'opnsense_auditor'
```

## S-06: 실제 차단 시험과 현재 유효 정책

현재 기존 auditor의 인터페이스 API는 성공했고, 규칙/규칙 ID API는 실제 403이었다. 권한을 자동 확대하거나 운영 연결을 변경하지 않았다. 필요한 후속 조건은 다음과 같다.

1. 관리자가 기존 non-root auditor에 **필요한 읽기 API만** 허용하거나, 아래 콘솔 원본으로 현재 유효 PF 규칙을 수집한다. 새 영구 키 발급은 필요 조건이 아니다.
2. 기존 콘솔 접근·설정 백업·복구 경로를 확보한다. 현재 관리 정책의 허용 IP/인터페이스/포트와 우선순위를 확인한 뒤에만 격리 LAB 정책을 개선한다.
3. 인가 관리 출발지와 **실제로 별개인 비인가 출발지**에서 같은 관리 목적지·포트를 시험한다. Windows LAN에서 WAN 주소로 접속한 것을 WAN 출발지 시험으로 바꾸지 않는다.
4. 원본 로그의 출발지·목적지·포트·시각·PF 규칙/카운터를 연결해 실제 허용/차단을 입증한다. 단순 timeout이나 수동 JSON 선언만으로 PASS하지 않는다.

OPNsense VM 콘솔에서 전달한 [읽기 전용 묶음 스크립트](../scripts/collect_opnsense_selected.sh)를 한 번 실행하면 제품 버전, active PF, 상세 카운터, 리스너, 인터페이스, 비밀을 제외한 관리 설정과 해시를 모은다. **이번 작업에서는 이 콘솔 스크립트 자체를 VM 안에서 실행하지 못했다.**

```sh
sh collect_opnsense_selected.sh /root/kisa-console-NEW_TIMESTAMP
```

출력 경로가 이미 있으면 중단한다. `/conf/config.xml` 원본·암호·API Secret·개인키는 복사하지 않는다. 누락 XML 필드를 자동으로 안전하다고 해석하지 않는다. 실제 접속 시험은 별도로 필요하며 콘솔 수집 자체가 S-06 PASS가 아니다.

## S-07: 확인된 TLS와 전체 관리 채널의 차이

현재 실제 CA/IP SAN 검증 TLS 1.3, HTTP→HTTPS 301과 비밀번호 평문 로그인 폼 부재를 확인했다. 그러나 전체 관리 서비스/인터페이스 설정·제품 버전·평문 채널 인벤토리는 확보하지 못했다. 위 콘솔 원본에서 관리 프로토콜·리스너·인터페이스를 확인하고 각 적용 경로의 TLS/SSH·인증서/호스트키를 실제 대조해야 한다. 포트 22/23의 timeout을 “서비스 비활성화” 증거로 바꾸지 않는다. 브라우저 보안 경고를 우회하거나 TLS 검증을 생략한 결과를 신원 검증으로 쓰지 않는다.

## CA-09: 기술적 수집을 정기 운영 실적으로 바꾸지 않기

기존 독립 private-only VPC에서 SG 2개/NACL 2개 전체를 실제 조회하고 현재 기술 검토 기록을 남겼다. CA-07은 그 내부 전용 설정 범위에서 PASS지만, CA-09의 규칙별 필요성 승인과 실제 정기 검토 이력은 미입증이다.

- 각 SG/NACL의 방향·출발지·목적지·프로토콜·포트·순서·연결 자산과 규칙별 목적을 실제 검토한다. 기본 SG/NACL도 누락하지 않는다.
- 검토 담당·대상·주기와 예외/불필요 규칙 판단을 기록하고, 변경이 필요하면 승인된 기존 독립 LAB 범위에서 별도 검토한다. 이번 실행은 AWS 읽기 전용이며 정책을 바꾸지 않았다.
- 과거 실제 수행 기록이 있다면 원래 시각·내용·원시 자료를 확인해 연결한다. 2026-11-06 구성 before/after를 정기 검토 완료로 재명명하지 않는다.
- 과거 기록이 없다면 실제 다음 회차를 수행한 후 그때의 날짜와 증거를 남긴다. 같은 세션에서 반복 수집한 것을 여러 정기 회차로 부풀리지 않는다.

이 조건이 충족되기 전에는 16/16 문구를 사용하지 않는다. 기존 CT-01 FAIL·IAM-03 검토 필요, OPNsense의 다른 미완료 항목은 선정 16개의 결과로 덮어쓰지 않는다.
