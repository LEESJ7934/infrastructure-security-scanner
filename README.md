# 인프라 보안 취약점 진단 스캐너

Python 기반 보안 진단 프로젝트입니다. 서비스·버전 식별과 CVE 후보 분석을 시작으로 인프라 설정 점검, 개선 전후 재점검, JSON/PDF 보고서 생성을 구현했습니다.

초기 스캐너는 팀 프로젝트로 개발했으며, 서버·네트워크·DBMS·WEB/WAS·보안장비·AWS 진단과 DVWA 웹 취약점 실습은 개인 후속 작업으로 확장했습니다.

## 주요 기능

| 구분 | 구현 내용 |
| --- | --- |
| 서비스·취약점 탐색 | TCP/UDP 스캔, 배너·버전 식별, CVE 후보 매핑, CVSS·EPSS·KEV 기반 우선순위 검토 |
| 인프라 설정 진단 | Linux, Windows Server, MySQL, Nginx/Tomcat, 네트워크 장비, OPNsense, ModSecurity, AWS |
| 진단 판정 | 설정·응답을 기준과 비교해 PASS / FAIL / NEEDS_REVIEW 등으로 구분 |
| 재점검·보고 | 개선 전후 비교, 증적 기록, JSON/PDF 보고서 |
| 웹 보안 실습 | DVWA SQL Injection, Reflected XSS, File Upload 진단 및 시큐어코딩 개선 |

**진단 흐름:** 승인된 대상 지정 → 설정·서비스 수집 → 기준별 판정 → 개선 → 재점검 → 보고서 작성

## 검증 결과

| 실습 | 결과 |
| --- | --- |
| KISA 기준 선정 16개 항목 | **PASS 13 / NEEDS_REVIEW 3** (2026-11-09) |
| Linux·MySQL Replay LAB | **10건 FAIL → PASS** |
| WEB/WAS 별도 LAB | **8건 FAIL → PASS** |
| DVWA 웹 취약점 3종 | **자동 재검증 37건 통과** (SQLi 11, XSS 9, File Upload 17) |

각 결과는 **서로 다른 실습 환경과 시점**에서 얻었으며 합산하지 않습니다. KISA 16개 항목 중 OPNsense 2건과 AWS 1건은 검증 조건이 부족해 NEEDS_REVIEW로 남겼습니다.

- [KISA 16개 항목별 결과](docs/kisa-2026-final-scope-result.md)
- [인프라 진단 근거 및 한계](docs/audit-evidence-mapping.md)
- [DVWA 웹 취약점 개선·재점검](docs/web-dvwa/README.md)

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

실제 점검·개선 결과는 격리 LAB 또는 승인된 실습 자산에 한정됩니다. CVE 후보를 취약점 확정으로 취급하지 않으며, 증적이 불충분한 항목은 PASS로 처리하지 않습니다.

2026-11-16 기준 DVWA 자동 테스트 37건은 통과했습니다. 저장소 전체 Windows 로컬 테스트에는 WSL `/bin/bash` 부재로 인한 실패 1건과 Suricata 원본 증적 누락으로 시작되지 못한 테스트가 남아 있습니다. 자세한 내용은 [DVWA 검증 기록](docs/web-dvwa/README.md)에 기록했습니다.
