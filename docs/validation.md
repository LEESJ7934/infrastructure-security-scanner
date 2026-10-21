# 검증 범위 및 결과

본 문서는 **자동 테스트 / 격리 Docker 통합 검증 / 승인 EC2·로컬 실습**을 구분해 기술합니다. 테스트 통과를 실제 운영환경의 전체 보안 검증 완료로 해석하지 않습니다.

## 1. 자동 테스트와 CI

- Python 전체 회귀 테스트 **330개 통과** ([기본 CI 실행 기록](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39456387487))
- 승인 Scope, 서비스 fingerprint, CVE 영향 버전 매핑, 증적 중복 방지, 위험도 평가, 스냅샷 보고서, 비밀정보 검사 등 테스트
- [격리 Docker 통합 CI](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39453811884): MySQL V6→V7 마이그레이션, 기존 데이터 보존, FTP·SSH·HTTP·DVWA·Nuclei 실습, 증적 해시 및 JSON/PDF 생성 확인

실행:

```powershell
py -m unittest discover -s .\tests -p "test_*.py" -v
py -m compileall -q .\asset_management .\scanner .\db .\scripts .\analysis .\verification .\api
py .\scripts\check_secrets.py
docker compose -f .\docker\docker-compose.yml config --quiet
```

## 2. EC2 및 로컬 실습

2026-10-20 기준 승인된 실습 자산에서 수집한 관찰 결과입니다.

| 검사 항목 | 관찰 결과 | 해석 |
|---|---|---|
| FTP 익명 인증 | `230 Login successful` | 해당 서비스의 익명 인증 허용 설정 확인 |
| SSH 기본 인증 정책 | 비밀번호 인증 비활성 | 확인 범위 내 기본 설정이며 전체 SSH 정책 검증은 아님 |
| HTTP 보안 헤더 | 4종 헤더 누락 | 해당 응답의 보안 헤더 미설정 |
| DVWA SQLi 실습 | 정상 1행 / 우회 5행 | 승인된 실습 응답에서 조건 우회 확인 |
| 로컬 정상 HTTP | 점검 항목 미발견 | 특정 검사에 한정된 NOT_DETECTED |

저장 결과 화면에서 EC2 4건과 로컬 HTTP 1건의 증적 **5/5 MATCH**, 보고서 Snapshot MATCH 및 VERIFIED를 확인했습니다. 여기서 MATCH는 저장된 증적의 내용 무결성 비교이며, 원격 출처 인증·전체 취약점 커버리지를 뜻하지 않습니다. 원본 보고서 파일을 별도로 독립 재해싱한 결과와도 구분합니다.

## 3. 같은 대상의 개선 전후 검증 — Docker

GitHub Actions 일회용 Docker 환경에서 동일한 서비스 대상으로 조치 전후를 검증했습니다.

| 검사 | 조치 전 | 개선 후 동일 대상 재점검 |
|---|---|---|
| FTP 익명 인증 | CONFIRMED | NOT_DETECTED |
| HTTP 보안 헤더 | POTENTIAL | NOT_DETECTED |
| Nuclei HTTP 템플릿 | POTENTIAL | NOT_DETECTED |

**실제 AWS EC2 설정을 변경한 결과가 아닙니다.** 별도 SQLite SQL 앱과 DVWA의 결과도 같은 서비스의 개선 전후로 취급하지 않습니다.

## 4. 판정 상태

| 상태 | 의미 |
|---|---|
| CANDIDATE | 서비스·버전과 공개된 영향 범위가 일치하는 후보 |
| POTENTIAL | 특정 설정 또는 템플릿 기준 위험 가능성 |
| CONFIRMED | 해당 검사·실습에서 직접 확인한 동작/설정 (CVE 확정과 구분) |
| NOT_DETECTED | 실제 수행한 검사 범위에서 미발견 |
| ERROR / INCONCLUSIVE | 검사 실패 또는 결론 도출 불가 |
| NOT_TESTED | 유효 증적 없음 또는 해당 범위 미검사 |

CVE 후보 4개는 검토한 공식 영향 범위에 한정합니다. 미일치는 안전 판정이 아닙니다. CVSS·EPSS·KEV는 검토 우선순위 자료이며, 취약 확정 기준이 아닙니다.

## 5. 대표 증적

- [서비스 식별·Scope](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/0806691a1baf8df509376b3de8e69d3a017e51a2/docs/images/01-scope-service.png)
- [CVE 후보 판단](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/0806691a1baf8df509376b3de8e69d3a017e51a2/docs/images/02-cve-candidate.png)
- [설정·실습 증적 검증](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/0806691a1baf8df509376b3de8e69d3a017e51a2/docs/images/05-v7-integrity.png)
- [Docker 동일 대상 재점검](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/0806691a1baf8df509376b3de8e69d3a017e51a2/docs/images/06-docker-retest.png)
- [통합 보고서 무결성](https://raw.githubusercontent.com/LEESJ7934/infrastructure-security-scanner/0806691a1baf8df509376b3de8e69d3a017e51a2/docs/images/07-integrated-report.png)

### 검증 한계

AWS Security Group 설정만으로 실제 인터넷 도달성을 확정할 수 없습니다. SSH 정책은 조건부 Match나 실행 인수까지 전부 포함하지 않습니다. Nuclei 템플릿 매칭을 특정 CVE의 자동 확정으로 해석하지 않습니다. 실습환경 검사와 실제 운영환경 보안 적합성·ISMS-P 인증은 구분합니다.
