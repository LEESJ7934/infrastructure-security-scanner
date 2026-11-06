# Windows Server 초기 확장 (공개용 기술 설명)

공통 AuditRule/Observation/evaluate 엔진을 재사용하는 오프라인 Windows Server 설정 진단이다. 9개 내부 WIN-LAB 항목은 Guest, 암호 길이·복잡성·잠금, Spooler, 방화벽, SMB 및 시스템 감사 설정을 다룬다. KISA 공식 항목 매핑이나 인증을 주장하지 않는다.

- 기본 STRICT 모드는 승인·범위·해시·시각 등 증적 신뢰도를 별도로 검토한다.
- `--mode LAB`은 개인 실습 기준과 확인된 설정값으로 평가하며, 조직 승인 문서를 요구하지 않는다.
- 자동 수집과 사용자 PowerShell 확인은 분리한다. 수동값을 원본 JSON에 삽입하지 않는다. 현재 값이 충돌하면 PASS를 강제하지 않는다.
- 읽기 전용 PowerShell 수집기는 Server 제품/역할을 확인하고, 로컬·도메인 정책을 구분한다. 비밀번호나 인증 토큰을 수집하지 않는다.
- 서버 설정을 변경하는 기능은 없다. 실행기는 명시적인 저장 JSON만 읽는다.
- 감사는 표시 언어 대신 GUID 기반 시스템 조회를 사용한다. 실제 이벤트 전달이나 전체 유효 정책을 검증했다고 주장하지 않는다.
- JSON/PDF는 새 출력 디렉터리에 생성한다. 기존 Day5 보고서는 변경하지 않는다.

개인 수집본, 수동 확인 기록, VM 이미지, 실제 보고서 및 상세 실습 일지는 공개 소스 checkpoint에 포함하지 않는다. 상세 로컬 일지와 증적은 원래 경로와 별도 로컬 백업에 보존한다. 저장소 테스트는 합성 자료를 사용하며 실제 서버 실행 결과와 구분한다.

```powershell
.\.venv\Scripts\python.exe -B -m scripts.run_windows_audit
.\.venv\Scripts\python.exe -B -m unittest tests.test_windows_audit tests.test_windows_policy tests.test_windows_lab
```

`rules/windows-server-personal-lab.json`은 내부 LAB 기준이며 `rules/windows-server-lab.json`의 DRAFT를 승인 완료로 만들지 않는다. 실제 환경별 적용성 확인이 필요하다.
