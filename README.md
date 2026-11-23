# 인프라 보안 취약점 진단 스캐너

> **2026 신입 기술진단 지원 자료**  
> [근거 중심 대표 사례 3건](docs/recruiting-evidence-brief.md) · [KISA 선정 항목 × 기술면접 연결표](docs/recruiting-kisa-interview-map.md) · [기술면접 질문 16개](docs/recruiting-technical-interview.md)  
> 실제 고객사 수행이 아닌 격리 LAB·개인 후속 작업입니다. 일부 판정·운영조건은 미검증으로 구분합니다.

Python 기반 보안 진단 프로젝트입니다. 서비스·버전 식별과 CVE 후보 분석을 시작으로 인프라 설정 점검, 개선 전후 재점검, JSON/PDF 보고서 생성을 구현했습니다.

초기 스캐너는 팀 프로젝트로 개발했으며, 서버·네트워크·DBMS·WEB/WAS·보안장비·AWS 진단과 DVWA 웹 취약점 실습은 개인 후속 작업으로 확장했습니다.

## 프로젝트 핵심

초기 팀 프로젝트에서 개발한 서비스·버전 기반 취약점 탐색 스캐너를 개인 후속 작업으로 확장했습니다. 격리 LAB에서 서버·네트워크·DBMS·WEB/WAS·보안장비·AWS의 설정을 직접 확인하고 **취약점 식별 → 개선 → 동일 범위 재점검**을 수행한 기록입니다.

| 구분 | 핵심 내용 |
| --- | --- |
| **진단 대상** | Linux·Windows Server, 가상 Router/Switch, MySQL, Nginx·Tomcat, OPNsense·ModSecurity·Suricata, AWS |
| **진단 과정** | 점검 범위·자산 식별 → 설정·서비스·패킷 수집 → KISA 기준 비교 및 근거 판단 → 개선 → 동일 조건 재점검 → 증적·보고서 |
| **핵심 검증 성과** | 계정·권한·SSH 정책 개선, 웹/DB 설정 재점검, 방화벽 접근통제 및 로그 대조 (Suricata 과거 LAB는 최종 성과 집계에서 제외) |
| **검증 범위** | 승인된 격리 LAB의 실제 관찰만 기술. 일부 운영 이력·관리 경로·활성 시그니처 전체는 미검증 범위로 구분 |

**핵심 접근:** 단순한 포트 개방이나 CVE 후보 식별을 취약 확정으로 처리하지 않고, 적용 설정·실제 응답·접속 시험·로그를 서로 대조해 판단합니다.

## 진단 대상과 수행 내용

| 진단 영역 | 대표 점검 내용 |
| --- | --- |
| Linux / Windows Server | SSH root 직접 로그인, 주요 파일 권한, Guest·계정 잠금·암호 정책, 방화벽 |
| 가상 Router / Switch | FRRouting·Linux bridge·nftables 기반 접근제어 및 불필요 리스너 |
| MySQL | 불필요 계정, 원격 root, 관리자 권한, Host 기반 접속 제한, 암호화 설정 |
| Nginx / Tomcat | 디렉터리 목록화, 불필요 기본 파일, 서비스·버전 노출 및 오류 응답 |
| OPNsense / ModSecurity | 관리자 접근 제한, PF 규칙·로그, HTTPS 관리, WAF 설정·감사 로그 |
| Suricata IDS / IPS | LAN ICMP 시험 패킷 Alert, Netmap Drop, 차단 해제 후 통신 복구 |
| AWS | 독립 LAB VPC의 서브넷·라우팅·SG·NACL·IAM·로깅 구성 조회 및 검토 |
| 웹 취약점 실습 | DVWA SQL Injection·Reflected XSS·File Upload 개선 및 자동 재검증 |

## 대표 개선·재점검 사례

| 대상 | 취약점 진단 및 개선 과정 | 실제 확인 근거 |
| --- | --- | --- |
| Linux·MySQL 별도 LAB | SSH 정책·계정·권한·원격 DB 접근을 개선 | 개선 전후 설정·권한·접속 결과로 **10건 재점검** |
| WEB/WAS 별도 LAB | Nginx 디렉터리 노출, Tomcat 불필요 배포·설정 등을 개선 | 파일 목록·유효 설정·HTTP 응답으로 **8건 재점검** |
| OPNsense | 관리자 PC 허용, 비인가 LAN/WAN 접근 차단 규칙 정비 | 실제 PF 규칙, 허용·차단 접속 시험과 Live View 로그 대조 |
| Suricata | IDS Alert → IPS Drop → 규칙 해제 및 정상 복구 | 시험 ICMP 패킷 경고 기록, 차단 후 Ping 4/0, 복구 후 4/4 |
| AWS 독립 LAB | SG·NACL 등 접근제어 현황과 과도한 허용 가능성 점검 | SG 2개·NACL 2개 실측 수집; 규칙별 승인·정기 검토 이력은 별도 확인 필요 |
| DVWA | SQLi·XSS·파일 업로드 방어 로직 개선 | 자동 재검증 **37건 통과** |

위 사례의 횟수는 **서로 다른 실습 환경·시점의 기록**이므로 하나의 취약점 총계로 합산하지 않습니다. Suricata는 **시험용 IP/ICMP 규칙의 탐지·차단 기능**을 검증한 것이며 실제 공격 시그니처의 탐지 성능을 검증한 것은 아닙니다.

## 검증 범위 및 상세 진단 대장

주요 성과는 **점검 설정, 발견 내용, 개선 조치, 재점검 결과, 증적**을 중심으로 기술했습니다. `PASS / FAIL / NEEDS_REVIEW / NOT_TESTED` 상태값은 판정 엔진과 상세 진단 대장에 그대로 유지합니다.

- 기존 KISA 선정 **16개**와 Suricata S-19·S-23을 추가한 **확장 18개**는 서로 다른 점검 범위입니다.
- 기존 16개 대장에는 **15 PASS / 1 NEEDS_REVIEW**가 기록돼 있으나, **S-06은 사용자 요청으로 PASS 처리했으며 일부 관리 주소 접근 경로가 미검증**입니다. 이를 전체 경로 검증 완료로 해석하지 않습니다.
- AWS CA-09의 실제 운영 승인 및 정기 검토 이력은 확인되지 않았습니다.
- 확장 항목 S-19·S-23의 **LAB 기능 시험은 2건 PASS**이나, KISA 전체 항목의 추가 시험 조건은 남아 있습니다.
- 실제 증적 원본 및 인증정보가 포함된 자료는 비공개로 보관합니다. 공개 보고서 샘플은 합성 데이터입니다.

세부 판정과 근거는 아래 문서에서 확인할 수 있습니다.

- [KISA 선정 16개 결과와 OPNsense 재점검 한계](docs/kisa-2026-final-scope-result.md)
- [Suricata S-19·S-23 확장 진단](docs/kisa-2026-suricata-s19-s23-extension.md)
- [AWS CA-09 후속 검증 및 관리 접근통제 한계](docs/kisa-2026-external-followup.md)
- [인프라 점검 근거와 한계](docs/audit-evidence-mapping.md)
- [DVWA 웹 취약점 개선·재점검](docs/web-dvwa/README.md)
- [Notion 상세 프로젝트 설명](https://app.notion.com/p/300fef5673598095a2a5cc5107dcb62c)

## 주요 구현 기능

| 기능 | 구현 내용 |
| --- | --- |
| 서비스·취약점 탐색 | TCP/UDP 스캔, 배너·버전 식별, CVE 후보 매핑, CVSS·EPSS·KEV 우선순위 검토 |
| 인프라 설정 진단 | Linux·Windows·MySQL·Nginx/Tomcat·가상 네트워크·보안장비·AWS 설정 수집 |
| 근거 기반 판정 | 수집 설정과 검사 응답을 선택한 KISA 기준·LAB 정책과 비교 |
| 재점검·보고 | 개선 전후 비교, 결과 상태·증적 이력 관리, JSON/PDF 보고서 생성 |
| 웹 취약점 실습 | DVWA SQLi·XSS·파일 업로드 진단 및 시큐어코딩 개선 |

## 코드 구성

| 경로 | 내용 |
| --- | --- |
| [scanner/](scanner/), [analysis/](analysis/) | 서비스 탐색, 취약점 후보 및 위험도 분석 |
| [config_audit/](config_audit/) | 서버·DBMS·WEB/WAS·네트워크·보안장비 설정 진단 |
| [cloud_security/](cloud_security/) | AWS 수집 및 진단 범위 관리 |
| [lab/dvwa-sqli-retest/](lab/dvwa-sqli-retest/) | DVWA 개선 PHP와 HTTP·브라우저 회귀 테스트 |
| [docs/](docs/) | 진단 기준, 실습 기록, 증적 및 재점검 문서 |

**사용 기술:** Python, Docker, PowerShell, MySQL, AWS(boto3), PHP, Burp Suite, GitHub Actions

## 실행

Python 3.12 기준입니다. 전체 단위 테스트는 일부 로컬 증적과 실행 환경에 의존합니다.

```bash
python -m pip install -r requirements.txt -r requirements-reporting-test.txt
python -m unittest discover -s tests -p "test_*.py"
```

공개용 보고서 샘플 생성:

```bash
python -m scripts.generate_report_sample
```

- [보고서 PDF 샘플](examples/integrated-report-sample/sample-integrated-report.pdf)
- [보고서 JSON 샘플](examples/integrated-report-sample/sample-integrated-report.json)
- [GitHub Actions](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/workflows/ci.yml)

공개 보고서 샘플은 **합성 데이터**이며 실제 진단 결과가 아닙니다. DVWA 최종 실측 보고서와 원본 증적은 로컬에 별도 보관합니다.

## 검증 범위

실제 점검·개선 결과는 격리 LAB 또는 승인된 실습 자산에 한정됩니다. CVE 후보의 확인 근거와 미검증 조건을 기록합니다. 선정 대장에는 증적 기반 PASS와 사용자 지정 판정을 구분해 표시합니다.

2026-11-16 기준 DVWA 자동 테스트 37건은 통과했습니다. 저장소 전체 Windows 로컬 테스트에는 WSL `/bin/bash` 부재로 인한 실패 1건과 Suricata 원본 증적 누락으로 시작되지 못한 테스트가 남아 있습니다. 자세한 내용은 [DVWA 검증 기록](docs/web-dvwa/README.md)에 기록했습니다.

## 2026-11-19 신뢰성 개선 검증

- 스캔 상태 구분: TCP 연결 거부와 타임아웃/네트워크 오류를 구분하여 미확인 상태를 임의의 `closed`로 처리하지 않도록 개선했습니다.
- 버전·CVE 이력: 현재 관찰과 과거 확인 이력을 구분하여 서비스가 변경된 후 오래된 취약점 판정을 현재 상태로 오인하지 않도록 보강했습니다.
- 시간·증적: UTC 시각 변환, 민감 배너/헤더 보호, DB 실패 전 원시 JSON 보존, 결과 근거 기록을 보강했습니다.
- 데이터 이력: 선택적 `sql/migration_v8.sql`은 실행별 관찰 및 취약점 이력 관계를 보존하기 위한 구조입니다. 실제 운영 DB에 자동 적용되지 않았습니다.
- **로컬 테스트(2026-11-19):** 1,354개 중 1,332개 통과, 실패·오류 0, 22개 건너뜀(원본 증적 부족 19개, 별도 MySQL 환경 미지정 3개). WSL 기본 배포판 `docker-desktop`이 `/bin/bash`를 실행하지 못한 문제는 Git Bash를 우선하도록 테스트 프로세스 PATH만 조정해 해결했습니다.
- **범위:** 격리 LAB 및 합성 테스트 결과는 실장비·운영 AWS의 전체 검증을 뜻하지 않습니다. Suricata의 과거 별도 LAB 기록은 최종 신뢰성 개선 성과 집계에서 제외합니다.
