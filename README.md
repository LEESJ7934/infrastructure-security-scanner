# 인프라 보안 진단 스캐너
**Infrastructure Security Scanner | 보안 진단·증적 관리 프로젝트**

승인된 자산의 **서비스 식별 → 취약점 후보 분석 → 설정·실습 검증 → 위험 우선순위 → 증적·재점검 → JSON/PDF 보고서**를 연결한 보안 진단 프로젝트입니다.

- **팀 프로젝트:** 2025.12 ~ 2026.01 (이후 개인적으로 기능 확장 및 검증 보완)
- **기술:** Python, MySQL, Docker, AWS EC2/VPC, Nuclei, NVD CVSS, FIRST EPSS, CISA KEV
- **포트폴리오:** [프로젝트 설명 및 검증 화면](https://app.notion.com/p/300fef5673598095a2a5cc5107dcb62c)

## 1. 문제와 개선 방향

초기 포트 스캔만으로는 **점검 승인 여부, 자산 중요도, 실제 서비스, 취약점 판단 근거 및 조치 이력**을 설명하기 어려웠습니다. 따라서 단순 열린 포트 목록이 아니라 **관찰한 사실과 추가 확인이 필요한 판단을 분리해 기록하는 구조**로 확장했습니다.

```text
승인 Scope → 자산·포트 스캔 → 서비스/버전 식별 → CVE 후보
                    ↓                             ↓
             자산·관찰 이력                 읽기 전용 검증
                    └─────────┬───────────────────┘
                        CVSS/EPSS/KEV + 자산 맥락
                                  ↓
                          증적·조치·재점검
                                  ↓
                          JSON/PDF 보고서
```

## 2. 핵심 구현

| 영역 | 구현 및 판단 근거 |
|---|---|
| 점검 범위 | IP/CIDR/호스트 대상 승인 Scope, 허가 유효기간, 실행 한도, dry-run |
| 자산 관리 | 자산 ID, 중요도·담당자·개인정보 처리·노출 여부, 변경 전후 감사이력 |
| 서비스 식별 | 포트 번호 추측 대신 서비스 응답을 기반으로 제품·버전을 기록 |
| CVE 후보 | 공식 공지를 검토한 4개 CVE의 영향 범위를 비교하며 **CANDIDATE는 확정 취약점과 구분** |
| 검증 | FTP·SSH·HTTP 설정 및 DVWA 실습, Nuclei 결과를 검사 유형별 증적으로 보관 |
| 우선순위 | CVSS·EPSS·KEV와 자산 맥락을 고려하되 우선순위와 취약 확정 여부를 별도 관리 |
| 보고서 | 검사 시각·대상·판정·증적 해시·조치이력·누락 사항을 JSON/PDF로 연결 |
| AWS 확장 | EC2·Security Group 읽기 전용 자산/설정 점검, 발견과 스캔 승인을 분리 |

## 3. 검증 사례 및 결과

**① 승인 EC2·로컬 실습 결과 (2026.10):** FTP 익명 로그인 성공, SSH 비밀번호 인증 비활성, HTTP 보안 헤더 4종 누락, DVWA 정상 조회 1행 대비 우회 입력 5행을 각각 관찰했습니다. 저장 결과 화면에서는 EC2 4건과 로컬 HTTP 1건의 **증적 5/5 MATCH 및 Snapshot MATCH**를 확인했습니다. 이는 해당 증적의 내용 일치 확인으로, 전체 시스템의 안전성이나 모든 검사 완료를 뜻하지 않습니다.

**② 별도 Docker 통합 검증:** 동일한 FTP 실습 서비스의 익명 로그인 차단 전후, 동일 HTTP 서비스의 보안 헤더 적용 전후를 검사하고 Nuclei 결과도 재점검했습니다. **CONFIRMED/POTENTIAL → NOT_DETECTED**는 *해당 검사 범위*에 한정되며, 실제 EC2 설정을 변경·개선했다는 의미가 아닙니다.

**③ 회귀 테스트와 보고서:** Python 회귀 테스트 330개 및 Docker/MySQL/Nuclei 통합 검증을 GitHub Actions에서 수행했습니다. [기본 CI](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39456387487) · [격리 통합 검증](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39453811884)

### 대표 증적 화면

| 승인 범위·서비스 식별 | 설정 검증·증적 |
|---|---|
| ![Scope와 서비스 식별](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/main/docs/images/01-scope-service.png) | ![검증 결과 무결성](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/main/docs/images/05-v7-integrity.png) |

| 동일 Docker 서비스 재점검 | 통합 보고서 검증 |
|---|---|
| ![FTP HTTP 개선 후 재점검](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/main/docs/images/06-docker-retest.png) | ![JSON PDF 통합 보고서](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/main/docs/images/07-integrated-report.png) |

> 화면은 각각의 실습 시점 결과입니다. 이미지에 포함된 판정 상태는 해당 검사·환경의 결과이며, CVE 확정이나 전체 운영환경 안전 판정을 의미하지 않습니다.

## 4. 설계상 중요한 구분

- **CANDIDATE / POTENTIAL / CONFIRMED:** 배너·버전 일치, 설정 위험 가능성, 해당 설정·실습 검증 결과를 구분합니다. FTP 허용 설정의 CONFIRMED가 특정 CVE 확정을 뜻하지는 않습니다.
- **NOT_DETECTED / ERROR / NOT_TESTED:** 미발견, 검사 실패, 검증 증적 미확보는 서로 다릅니다.
- **CVSS·EPSS·KEV:** 검토 우선순위를 판단하는 자료이지 취약점 확정 근거가 아닙니다.
- **SHA-256:** 증적 내용 일치를 검토하며 원격 출처 인증이나 전자서명을 대신하지 않습니다.
- **AWS Security Group:** 광범위한 접근 허용 설정을 찾지만 네트워크 전체 도달성을 단정하지 않습니다.

## 5. 주요 코드 및 기술 문서

- [설계·데이터 흐름](docs/architecture.md) · [DB 구조](docs/database_schema.md)
- [자산 및 Scope 관리](docs/asset_management.md) · [서비스/CVE 매핑](docs/service_cve_mapping.md)
- [AWS 구성](docs/aws_architecture.md) · [AWS 검증 절차](docs/aws_validation.md)
- [테스트·검증 기준](docs/validation.md) · [격리 실습환경](lab/README.md)
- 주요 구현: `scanner/`, `asset_management/`, `analysis/`, `verification/`, `cloud_security/`, `sql/`
- 테스트: `tests/`, `.github/workflows/`

## 6. 실행 개요

Windows PowerShell, Python 3.10 이상, Docker Desktop 기준:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
Copy-Item .env.example .env
docker compose -f docker/docker-compose.yml up -d
Copy-Item config/scope.example.json config/scope.local.json
```

로컬 설정의 비밀번호와 승인 대상을 실제 실습 환경에 맞춰 수정한 뒤, `py -m scripts.run_scan scan --target 127.0.0.1 --ports 22,80,443 --scope-file config/scope.local.json --dry-run`으로 승인 범위를 먼저 확인합니다. **허가받지 않은 외부 자산에는 실행하지 않습니다.** 자세한 순서는 위 기술 문서를 참고합니다.
