# 포트스캐너 검증 기록과 판단 기준

## 코드·자동 검증

Work에서 전체 Python 테스트 330개, 구문 검사, diff 공백 검사, 민감정보 검사를 수행합니다. 정확한 GitHub 실행 결과는 [기본 CI와 Docker 통합 Actions](https://github.com/LEESJ7934/infrastructure-security-scanner/actions)의 해당 커밋을 확인합니다.

일회용 Ubuntu Docker/MySQL CI는 V6 기존 스캔 보존 후 V7 적용, FK 무결성, 실제 FTP/SSH/HTTP, 초기 데이터만 사용하는 DVWA 읽기 전용 SQLi, 공식 Nuclei v3.11.1의 실제 프로세스, V7 저장·증적 해시, JSON/PDF 생성 경로를 검사합니다. 이전 성공 기록: [Day 15~17 통합 CI](https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39450382155).

최종 통합 검사에는 같은 HTTP·FTP 서비스의 개선 후 재점검, Nuclei 헤더 재점검, 별도 안전 SQL 앱을 연결했습니다. 새로운 CI의 성공을 확인한 뒤 그 실행을 실증 근거로 사용합니다. 기존 EC2에 CI Compose를 배포하거나 설정을 바꾸지 않습니다.

## 사용자 소유 EC2의 실제 관찰

2026-10-20 사용자가 EC2 SSM에서 실행해 공유한 결과이며 Work/CI가 독립적으로 AWS에 접속한 결과가 아닙니다.

| 항목 | 사용자 확인 결과 | 저장 검증 상태 |
|---|---|---|
| FTP 21 | 익명 인증 230 Login successful | 사용자 실측 확인, V7 추가 저장 대기 |
| SSH 22 | pubkeyauthentication yes / passwordauthentication no | 기본 sshd 설정 관찰, V7 추가 저장 대기 |
| HTTP 80 | HTTP 200, CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy 누락 | 사용자 실측 확인, V7 추가 저장 대기 |
| DVWA SQLi | 정상 1행→우회 5행, CONFIRMED | 사용자 확인 기준 Windows V7 scan 7/port 4 저장 및 MATCH |
| Nuclei | 사용자 EC2 실측 미확인 | 실행·V7 저장 대기 |
| EC2 설정 개선 | 미실행 | Docker CI의 개선과 구분 |
| 신규 Windows 정상 스캔·통합 보고서 | 미확인 | 실제 ID·생성 결과 확인 대기 |

## 상태와 무결성 해석

- `CANDIDATE`: 기존 V6의 CVE 후보. 버전 일치만으로 확정하지 않음.
- `POTENTIAL`: 설정상 위험 가능성 또는 Nuclei 템플릿 매칭. 개별 맥락·CVE 검증 필요.
- `CONFIRMED`: FTP 익명 인증 허용이나 DVWA의 읽기 전용 행 확대를 해당 증적으로 확인. CVE 확정과 별개.
- `NOT_DETECTED`: 실행한 특정 검사에서 발견하지 못함. 시스템 전체가 안전하다는 뜻이 아님.
- `NOT_TESTED`: 증적 없음, 오류 또는 판정 불가인 검사 커버리지. 실행 오류 행은 `ERROR/INCONCLUSIVE`로 보존.

신규 관찰은 검사 시각도 증적 SHA-256에 포함합니다. 기존 V7 이력은 삭제·재해시하지 않습니다. 기존 스키마를 유지하며 원본 해시·정제 JSONL 해시·DB 증적 해시·통합 스냅샷 해시의 대상을 구분합니다. 해시는 내용 일치 검사이며 전자서명/원격 출처 인증은 아닙니다.

동일 스캔·자산·포트·환경·검사 항목의 검증 성공 이력만 전후 비교합니다. 오류·해시 불일치·다른 앱·같은 시각은 조치 성공으로 묶지 않습니다. EC2 DVWA와 정상 SQLite 앱은 독립 비교이며 DVWA가 개선됐다고 표시하지 않습니다.

## 재현과 실환경 확인

[Day 15~17](day15_17_work1.md)에서 사용자 기존 V7과 실제 원본을 연결하고, [Day 18~20 실행 지침](day18_20_final.md)에서 Windows Nuclei·SSM 전달·최종 보고서 명령을 실행합니다. 운영 SSH·기존 FTP/DVWA 데이터·AWS 네트워크·기존 다크웹 컨테이너를 변경하지 않습니다.

실제 Windows MySQL 결과와 최종 보고서를 일반 Chat에서 확인하기 전에는 전체 실환경 검증 완료로 표기하지 않습니다. 기능은 main에 통합되어 있으며 문서 후속 변경은 별도 PR로 관리합니다. 문서 PR 병합에는 사용자 승인이 필요합니다.
