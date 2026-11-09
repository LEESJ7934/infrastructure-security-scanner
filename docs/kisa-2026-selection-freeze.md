# KISA 2026 선정 범위 동결 및 자산 목록

이 작업은 구현·수집 결과와 무관하게 공식 ID 16개를 분모로 유지한다. 항목별 모든 지정 자산이 충족되어야 해당 ID를 PASS로 집계한다. 미측정 자산을 제외하여 분모를 줄이지 않는다. 확장 7개 및 제어시스템·이동통신·PC·가상화는 이번 분모 밖이며 PASS가 아니다.

## 원문 확인

사용자 로컬 PDF 873쪽의 표지·주의사항과 아래 항목 본문 및 관련 제품 조치 사례를 직접 확인했다. 표지 2026, 공식 게시일 2025-12-24. SHA-256: `44fe393981b244147be6af7423d99dc15633c089fad0bcb296cbe2371dde812d`. [공식 배포](https://www.kisa.or.kr/2060204/form?lang_type=KO&postSeq=22). 항목별 판단은 일반 권고이며 기관 정책의 최종 결론이나 ISMS-P 인증을 의미하지 않는다.

요청의 축약 명칭을 PDF 정식 명칭으로 확장했다. 기존 후보표 WEB-04/07/16의 앞부분 '웹 서비스', S-06의 '보안 장비' 띄어쓰기, D-02/04/10 문구를 아래대로 고정했다. ID 변경은 없다. WEB-16은 본문의 정보 비노출 기준과 Nginx `server_tokens off` 제품 사례가 함께 있으므로 개인 LAB 프로파일은 제품명 단독 노출을 허용하고 버전·OS 노출을 금지한다. 제품명도 완전히 제거해야 하는 기관 정책과 동일시하지 않는다. W-04의 0은 비활성화이므로 양호로 인정하지 않는다.

## 자산

| 식별자 | 제품/버전 | 수집·접근 상태 |
|---|---|---|
| linux | Ubuntu 24.04 / OpenSSH (패키지 버전은 원시 보고서) | 일회용 Actions Docker Replay, 호스트 OS 전체 아님 |
| windows | Windows Server 2022 / 10.0.20348 | 별도 Actions standalone VM; 사용자 Hyper-V와 분리 |
| nginx | Nginx 1.30.6 | 기존 scanner-p2web; 현재 로컬 Docker 엔진 미실행 |
| tomcat | Tomcat 10.1.61 | 기존 scanner-p2web; 신규 선정 기준 실측 미완료 |
| mysql | MySQL 8.4.13 | 기존 Replay는 일부 내부 항목만 확인; 전체 계정/네트워크 증적 미완료 |
| opnsense | OPNsense, 실제 버전 재수집 필요 | 기존 수동·자동 시험은 역사적 기록; 이번 관리경로 실측 미완료 |
| aws | AWS EC2 VPC/SG/NACL API, 리전·독립 LAB 확인 필요 | 운영 자원 미변경, 이번 선정 기준 실측 미완료 |

## 공식 매핑과 판단·증적 요구

| ID | PDF 정식 명칭 | 쪽 | 지정 자산 | 기존 내부 점검 |
|---|---|---|---|---|
| U-01 | root 계정 원격 접속 제한 | 12 | linux | LINUX-LAB-001 |
| U-18 | /etc/shadow 파일 소유자 및 권한 설정 | 44 | linux | LINUX-LAB-003 |
| W-02 | Guest 계정 비활성화 | 178 | windows | WIN-LAB-001 |
| W-04 | 계정 잠금 임계값 설정 | 180 | windows | WIN-LAB-004 |
| W-08 | 계정 잠금 기간 설정 | 185 | windows | WIN-LAB-004 |
| W-64 | 윈도우 방화벽 설정 | 270 | windows | WIN-LAB-006 |
| WEB-04 | 웹 서비스 디렉터리 리스팅 방지 설정 | 280 | nginx, tomcat | WEB-LAB-N01 |
| WEB-07 | 웹 서비스 경로 내 불필요한 파일 제거 | 290 | nginx, tomcat | WAS-LAB-T02 |
| WEB-16 | 웹 서비스 헤더 정보 노출 제한 | 316 | nginx, tomcat | WEB-LAB-N02 |
| D-02 | 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용 | 600 | mysql | MYSQL-LAB-001 |
| D-04 | 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용 | 608 | mysql | MYSQL-LAB-005 |
| D-10 | 원격에서 DB 서버로의 접속 제한 | 628 | mysql | MYSQL-LAB-002 |
| S-06 | 보안 장비 원격 관리 접근 통제 | 363 | opnsense | FW-02/FW-03 |
| S-07 | 보안장비 보안 접속 | 364 | opnsense | FW-management |
| CA-07 | VPC 네트워크 서브넷 관리 | 860 | aws | VPC-01 |
| CA-09 | 접근 제어 설정 관리 | 862 | aws | SG-01/NACL-01 |

정확한 개인 LAB 조건, 조치 및 필수 필드는 `rules/kisa-2026-selected.json`에 있다. JSON에 있는 조건은 정규화 증적 검토 계약이며 장비에서 수집한 사실 그 자체가 아니다. 수동으로 true를 입력하면 실측 인증이 되지 않는다.

## 판정과 출처

`config_audit/kisa_2026.py`는 기존 AuditRule/Observation/evaluate 및 U-18/W-04/W-08 비교 함수를 재사용한다. 저장자료 값이 조건에 맞는 PASS와 실제 장비 출처 검증을 분리한다. 입력은 SYNTHETIC/SAVED_LAB/MANUAL_LAB만 허용하며 VERIFIED_LAB 자기선언은 거부한다. 오프라인 JSON의 verified_lab_pass는 항상 0이다. 검토자는 실제 워크플로 실행 SHA, 작업 로그, 원시 수집 파일과 수집 시각을 확인한 후 별도 실측 대장에 기록한다. 역사적 3건을 현재 스냅샷으로 합산하지 않는다.

코드 구현은 16개 정규화 조건의 판정 지원을 뜻한다. 새 자동 수집·재점검 경로는 Linux 2개와 Windows 4개다. WEB/MySQL/OPNsense/AWS는 기존 수집기·원시 자료와 아래 수동 검토 요구를 연결해야 하며, 전체 조건의 자동 수집 완료를 주장하지 않는다. 제품 버전이 알려지지 않거나 불일치하면 안전한 관찰값도 NEEDS_REVIEW다.
