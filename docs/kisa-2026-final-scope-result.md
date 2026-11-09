# KISA 2026 선정 범위 최종 진단 결과

선정 16개 중 **실제 실측 PASS 6개(37.5%)**, NOT_TESTED 10개. 전체 100% 목표는 미달성이다. 이 문서는 서로 다른 일회용 Linux/Windows LAB의 증적 대장이며 하나의 동시 스냅샷이 아니다. 고객사 프로젝트·주요정보통신기반시설 전체 진단·인증 완료를 뜻하지 않는다.

## 판단과 증적

873쪽 공식 PDF를 직접 대조한 매핑·자산·기준은 [동결 범위](kisa-2026-selection-freeze.md), 구조화 결과는 [JSON 증적 대장](kisa-2026-final-scope-result.json)에 있다. 자동입력에 VERIFIED_LAB를 선언해 PASS를 늘리는 기능은 없다. 아래 VERIFIED_LAB는 GitHub 실행 성공, 해당 단계의 assertions, 원시 JSON, 내려받은 ZIP 해시를 검토한 대장 표기다. 오프라인 재판정의 실측 집계 0과 구분한다.

| 항목 | 조치 전 | 조치 후 | 최종 | 원시 수집 시각(UTC) |
|---|---|---|---|---|
| U-01 | PermitRootLogin yes | no; TCP 22만 관찰; LAB의 Include/Match 없음 확인 | PASS | 2026-11-09T07:38:26.600807+00:00 |
| U-18 | root 소유 0666 | root 소유 정규 파일 0400, 링크 아님 | PASS | 같은 Linux 수집 |
| W-02 | RID 501 비활성 | 비활성 재확인(기존 PASS) | PASS | 2026-11-09T07:37:42.9252312+00:00 |
| W-04 | 임계값 10 | 5, secedit 재수집 | PASS | 같은 Windows 수집 |
| W-08 | 잠금/초기화 10/10분 | 60/60분, secedit 재수집 | PASS | 같은 Windows 수집 |
| W-64 | 유효 프로필 3개 활성 | ActiveStore 3개 활성 재확인(기존 PASS) | PASS | 같은 Windows 수집 |

한국 시간: Linux 2026-11-09 16:38:26, Windows 16:37:42. Windows 조치 전 별도 시각은 원본에 없으므로 만들지 않았다. Guest·방화벽을 FAIL→PASS 사례로 표현하지 않는다.

## 검증된 실제 실행

- [Linux U-01/U-18 실행](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/42580520040): before FAIL 2 → after PASS 2, 나머지 14 NOT_TESTED. 기존 내부 Linux/MySQL 10 PASS와 KISA 공식 10 PASS는 다르다. [원시 JSON 아티팩트](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/42580520040/artifacts/13656249112). ZIP SHA-256 `2f08a504230b825b15532986dec9b11450afbcc67a7f2a9ba1ecdad750c049fd`.
- [Windows 4개 실행](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/42580520062): standalone Server 2022의 실제 정책·Guest·ActiveStore 확인, 나머지 12 NOT_TESTED. [원시 JSON 아티팩트](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/42580520062/artifacts/13657425113). ZIP SHA-256 `b9721d328e044bc05454d599f2bf88b1b365f0496c180ac78c541506c19e34db`.
- 원시 파일의 수집 시각과 원본 상태는 변경하지 않는다. 공개 저장소에는 비밀이 없는 선택 필드의 요약·참조만 두고 원본 파일 전체는 비공개 보관한다. 새 아티팩트는 90일 보존이며 만료 전 개인 보관 필요. 해시는 파일 동일성 근거이고 단독으로 실제 출처를 인증하지 않는다.
- 과거 실행 42574765798(U-18), 42575461694(W-04/W-08) 및 과거 0640/10/30 기록은 이전 문서에 그대로 남긴다.

## 미완료 10개

| 항목 | 상태 | 완료에 필요한 원시 증거 |
|---|---|---|
| WEB-04 | NOT_TESTED | Nginx/Tomcat 전체 선정 location·servlet 설정과 실제 디렉터리 HTTP 시험 |
| WEB-07 | NOT_TESTED | 두 제품의 배포경로 전체 파일 목록·필요성 검토, HTTP 부재 시험 |
| WEB-16 | NOT_TESTED | 두 제품의 유효 설정 및 정상/오류 응답 헤더·본문 |
| D-02 | NOT_TESTED | 전체 계정 목록과 계정별 필요성·잠금 검토 |
| D-04 | NOT_TESTED | 전체 글로벌/동적 권한, 역할 상속·프록시·mandatory roles 및 인가 목록 |
| D-10 | NOT_TESTED | 전체 Host·방화벽 정책과 인가/비인가 실제 연결 시험 |
| S-06 | NOT_TESTED | 관리경로 전체 설정과 인가/비인가 IP 접속·PF/로그 상관 |
| S-07 | NOT_TESTED | 관리 TLS/SSH 실연결, 인증서/호스트키·평문 관리 노출 검토 |
| CA-07 | NOT_TESTED | 독립 LAB subnet/route/instance 공인주소 전체 정합성 검토 |
| CA-09 | NOT_TESTED | SG/NACL 전체 정책 및 실제 날짜의 주기적 검토 기록 |

로컬 Docker 엔진은 미실행이며 이 작업에서 기존 OPNsense/독립 AWS 접속 범위와 원시 증거를 확보하지 못했다. 기존 내부 PASS를 공식 선정항목 PASS로 재명명하지 않았다. 추가 후보 7개는 핵심 16개 미완료이므로 보류. VTY와 Linux 방화벽을 동일시하지 않는다.

## 구현·검증·기여

정규화 판정 16개, 새 실제 수집 경로 Linux 2개/Windows 4개. 다른 분야는 기존 수집기와 수동 검토 계약을 연결하는 구현이며 전체 자동 수집 완료가 아니다. 새 테스트 12개와 기존 회귀를 합쳐 로컬 1,328개 실행, 실패 0, 환경 의존 skip 22개. 비밀정보 검사·diff 공백 검사 통과. 원격 CI는 PR에서 별도 확인한다.

Codex는 코드·문서 수정, 커밋·PR, 자동 Actions 실습 및 증적 대조를 수행했다. 사용자의 기존 수동 실습은 기존 문서 출처 그대로다. 사용자가 이번 명령을 직접 수행했다고 주장하지 않는다. 면접 설명은 [대표 사례 자료](kisa-2026-interview.md), 남은 실행은 [재점검 절차](kisa-2026-retest-runbook.md).
