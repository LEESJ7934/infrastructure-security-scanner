# Phase2 최종 통합 범위

항목·실제 자료·판정 한계·면접 표현은 [포트폴리오 근거 매핑](portfolio-evidence-mapping.md)을 단일 기준으로 사용한다.
아래는 기존 코드/원본을 새로 조회하지 않고 2026-11-07에 대조한 요약이다.

| 분야 | 확인한 저장 자료와 한계 |
|---|---|
| Linux/MySQL | Phase2 Replay 10건 FAIL→PASS. 기존 Day2 개선 2건과 별개 |
| Windows | Server 2022 저장 JSON + 사용자 수동 확인의 LAB 재분석: PASS 8 / NEEDS_REVIEW 1, 개선 3건. 수동 baseline을 자동값으로 표시하지 않음 |
| Router/Switch | R03/R04 2건 개선, 별도 fabric LAB의 양방향 패킷 경유. Switch 관리면/VLAN은 미지원 |
| WEB/WAS | Nginx/Tomcat 8건 FAIL→PASS, 전후 프록시 health HTTP 정상 |
| OPNsense | FW-02/03/06 수동 한정 PASS, FW-04/05 NEEDS_REVIEW 유지 |
| ModSecurity | WAF 6개 PASS 요약. 원시 HTTP·감사 로그가 없어 현재 자료만으로 독립 차단 재확인 불가 |
| AWS | 독립 LAB 4건 개선 관찰. CT-01 FAIL 및 IAM-03 NEEDS_REVIEW 유지 |

실습별 숫자를 고유 취약점 총계로 합치지 않는다. 실제 JSON/PDF는 비공개 로컬 원본이며,
Windows 최종 LAB 보고서와 Network 전용 PDF는 현 프로젝트 보고서 폴더에서 확인하지 못했다.
문서별 초기 테스트 숫자는 당시 단계의 기록이며 [테스트 기준표](portfolio-evidence-mapping.md#테스트-기록과-기준)와 구분한다.

## 개발 코드 통합

- Windows Server: 읽기 전용 PowerShell 수집, LAB/STRICT 판정 분리,
  암호·감사 정책 분석, 수동 확인 출처 분리, 시각 검증 및 재점검 JSON/PDF.
- Router/Switch: FRRouting/Linux bridge 기반 설정 진단, nft JSON 범위 확인,
  별도 격리 LAB의 패킷 경유 분석. 실제 하드웨어 기능 지원을 주장하지 않는다.
- Nginx/Tomcat: 제품별 설정 수집·판정, 격리 Compose, 전후 비교 및 HTTP 정상 동작 확인.
- Linux/MySQL: 각 5개 내부 점검, 개선 상태 보존, 별도 Replay LAB,
  원본을 덮어쓰지 않는 JSON/PDF와 전후 비교.
- AWS: IAM/SG/VPC/NACL/CloudTrail/Flow Logs P1 8개, 오프라인·Mock·명시적
  live-read-only 수집 분리, 계정/리전/자산 범위, 전후 비교와 별도 Terraform root.
- 공통 AuditRule, Observation, evaluate(), 상태 모델 및 Day5 보고서 구조를 유지한다.

각 LAB 문서의 초기 준비 단계와 후속 실제 검증 기록은 시점이 다른 기록이다.
설정 PASS는 실제 도달 가능성·패킷 차단·로그 전달 또는 공식 인증을 의미하지 않는다.
개인 LAB 기준과 실제 출처·수집/재분석 시각·수동/자동 채널을 구분한다.

## 최종 보고서 제외 범위

**Suricata IDS/IPS는 이번 최종 통합 보고서의 검증 대상과 개선 완료 집계에서 제외한다.**
기존 IDS/IPS 소스, 규칙, 테스트, 과거 Day3/IPS 문서와 원본 증적은 삭제하지 않는다.
기존 문서의 역사적 IDS 결과는 이번 최종 보고서의 새로운 검증 결과가 아니다.
인라인 IPS의 실제 차단 성공을 주장하지 않으며 테스트의 합성 PASS도 대신 사용하지 않는다.
기존 실제 JSON/PDF 보고서를 재생성하거나 수정하지 않는다.

## 비공개 로컬 자료 보존

실제 계정/자산 scope, API 인증정보, .env, 원본 로그/증적/보고서, 가상환경,
Terraform state/backup/.terraform/개인 tfvars/plan 및 잠금 정보는 커밋하지 않는다.
공개 fixture는 합성 테스트 자료이며 실장비 증적이 아니다.
AWS LAB 삭제는 미완료이므로 state·개인 변수·증적 원본을 그대로 유지해야 한다.
브랜치 삭제는 이미 main에 포함된 Git 참조만 정리하며 실습 파일 삭제가 아니다.
실제 자원 정리에는 별도 계정·삭제 Plan 검증과 사용자 승인이 필요하다.

## 오프라인 검증

프로젝트 루트 PowerShell:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py"
```

실제 AWS/VM/Docker 기동·자산 변경은 이 Git 통합 작업의 검증에 포함하지 않는다.
Windows Bash 실행 환경 오류가 있으면 다른 실패와 구분하여 그대로 보고한다.
