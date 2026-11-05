# Day4 OPNsense 실습 종료 기록

완료 기준일: 2026-11-06 (Asia/Seoul). 브랜치: `feature/day4-opnsense`.

## 완료 범위

- 사용자 실장비 확인: Hyper-V OPNsense 실습 구성, LAN/WAN 인터페이스 및 관리/방화벽 정책 시험.
- 코드/로컬 증적 확인: 인터페이스 점검, 안전한 조회 전용 API 수집, 로그 limit=20 및 응답 잘림 오류 구분, PF 스냅샷 오프라인 분석, 로그·규칙 식별자 연계, 자동/수동 결과 분리.
- 수동 증적: FW-02/03/06 PASS 및 원본 첨부의 SHA-256 일치. FW-04/05는 NEEDS_REVIEW 유지.
- FW-06: 기존 허용 전사본·차단 Ping/ICMP 로그·후속 실제 복구 Ping 4/4를 보존. 복구 파일은 별도 시각의 후속 시험이며 이전 시험 시각으로 소급하지 않는다.
- FW-04/05의 전체성·시간대·규칙 연속성 한계는 추후 개선 과제다. Day4 종료를 위해 PASS로 바꾸지 않는다.

이번 마무리 작업은 파일 검토·증적 무결성 확인·문서 갱신·기존 unittest 실행·선택적 stage/commit만 수행한다. 신규 기능이나 추가 실장비 시험, 방화벽/권한 변경, 원격 push는 수행하지 않는다.

## 신규 FW-05 재시험 기록

실제로 존재하는 `evidence/day4/fw05-wan-tcp22-retest.json`을 확인했다. 파일 크기는 4,682바이트이며 SHA-256은 `6bcb21e9c3cab79b78ff32f99587ab72e9fc919f7b64c8fd0367c6bf6ce2b84c`다.

- 기록된 시험 시작/종료 UTC: `2026-11-05T18:19:13.6151520+00:00` ~ `2026-11-05T18:19:32.6239020+00:00`.
- 사용자 보고 결과: `Operation timed out`.
- 저장 로그 3건: `10.77.50.10:37623 → 10.77.50.1:22`, TCP, hn0, block.
- 로그 표시 시각: `2026-11-05T18:19:26` ~ `18:19:28` (이벤트 자체에는 offset 없음).
- `rulenr=6`, label은 `Default deny / state violation rule`. rid도 존재하며 기존 PF 기본 IPv4 차단 규칙의 label 값과 일치하는 후보임을 확인했다.
- 파일에 기록된 장비 설정 시간대는 `Etc/UTC`지만 event_timezone_basis가 독립 입증되지 않은 가정이라고 명시되어 있다. 시험 UTC 구간과 로그의 벽시계 표시가 맞아 보인다는 이유만으로 같은 타임라인이라고 확정하지 않는다.
- `rule_generation_continuity_verified=false`: 해당 PF 스냅샷이 시험 시점에도 동일 세대였다는 연속성 자료가 없다. rid/순번이 일치해도 최종 규칙 매핑이나 FW-05 자동 PASS로 승격하지 않는다.

실제 차단 로그가 있다는 사실과 역사적 규칙·시험의 충분한 연계가 입증됐다는 주장은 별개다. 이 파일을 신뢰 수집기 context로 변환하거나 검증되지 않은 시각/세대 값을 채우지 않았다. 기존 로그 파일과 수동 증적은 유지한다.

## 커밋 대상과 민감정보 경계

Day4 소스 5개, 테스트 4개, 문서 4개, 빈 템플릿 1개 및 실제 로컬 Day4 증적 17개만 대상으로 한다. 기존 `evidence/`·`screenshots/` 무시 규칙을 전역 해제하지 않고, 이번에 검사한 정확한 파일만 개별 force-add한다. 다른 날짜 증적이나 전체 디렉터리는 stage하지 않는다.

추가로 `.gitattributes`의 Day4 증적 경로에만 -text를 지정해 줄바꿈 자동 변환을 막는다. 원본 CRLF는 유효한 줄 끝으로 인정하되 다른 기본 whitespace 검사는 유지한다. Git clone/checkout 후에도 manual.json의 SHA-256 및 tar member와 외부 PF 파일의 바이트 일치가 유지되어야 하기 때문이다. 다른 경로의 줄바꿈 정책은 바꾸지 않는다. 총 commit 대상은 이 경로별 메타데이터 수정까지 32개 파일이다.

증적에는 사설 실습 주소, PF label 및 로그가 포함되지만 이번 요청에 따라 Day4 기록으로 포함한다. API Key/Secret, Authorization 값, .env, 비밀번호, 개인키·인증서 비밀키는 포함하지 않는다. PNG는 이전 시각 검토 당시의 해시와 대조하고, 텍스트 및 tar member도 검사한다. 정책 label, 시각·세대의 한계, 수동 전사본 출처는 숨기거나 과장하지 않는다.

과거 진행 문서에 있는 'commit을 하지 않았다'는 당시 단계의 기록이다. 최종 Git 이력은 이번 종료 commit으로 확인하며, commit hash는 commit 완료 후 종료 보고에 기록한다.

커밋 메시지: `feat: 4일차 OPNsense 방화벽 진단 및 실습 검증 완료`

## 테스트 기준

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_day4_log_rule_evidence tests.test_day4_pf_evidence tests.test_day4_audit tests.test_day4_manual_evidence -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py'
```

Day4는 162개 통과가 기준이다. 현재 전체 회귀 결과는 543개 중 542개 통과이며, 기존 Bash 문법 검사 1개가 Codex Windows 샌드박스의 NtCreateDirectoryObject 권한 제한(0xC0000022)으로 실패한다. 이를 테스트 삭제/수정/skip으로 숨기지 않는다. Day4 종료는 미검증 조건이 사라졌다는 뜻이 아니며, 환경 밖에서 기존 Bash 검사 재확인이 필요하다.
