# SAMPLE / 합성 데이터 / 실제 점검 결과 아님

채용 포트폴리오에서 보고서 구조와 미검증 상태 표현을 확인하기 위한 공개
예시입니다. 실제 25페이지 로컬 보고서를 복사·비식별화한 자료가 아닙니다.

- [공개 샘플 PDF](sample-integrated-report.pdf): Windows 맑은 고딕 기준 16페이지
- [합성 JSON](sample-integrated-report.json): 공통 모델, 합성 입력, 예시 라벨,
  미실행 상태, 가상 증적 인덱스 및 비교 결과
- [생성 코드](../../scripts/generate_day5_sample.py): 합성 입력의 유일한 출처

## 데이터와 판정의 의미

가상 자산 5개, 고유 자산·항목 9개, 시점별 레코드 13개를 사용합니다.
IP는 RFC 5737 문서용 대역 `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`에 속합니다. 운영자명과 시각도 고정된 합성 값입니다.
실제 장비·계정·패킷·로그·스크린샷·사용자 PC 경로를 사용하지 않습니다.

`illustrative_status`의 PASS/FAIL/NEEDS_REVIEW는 UI 설명용 라벨입니다.
실제 `status`/`reported_status`는 전부 **NOT_TESTED**입니다. 가상의
`sample://` 참조는 EXTERNAL_REFERENCE이며, 실제 파일 존재·기대 해시·계산
해시·검증 시각은 없습니다. VERIFIED 0건입니다. 조치 완료나 실제 정책
적용을 주장하지 않으며 비교 결과도 UNVERIFIABLE로 남깁니다.

JSON의 내용 해시는 합성 산출물의 콘텐츠 식별자일 뿐 장비 증적 검증이
아닙니다. 합성 시나리오 시각과 PDF의 고정 생성 메타데이터는 실제 수집
시각으로 해석하지 않습니다.

## 재현

프로젝트 루트에서 실행합니다.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-reporting-test.txt
.\.venv\Scripts\python.exe -B -m scripts.generate_day5_sample
.\.venv\Scripts\python.exe -B -m unittest tests.test_portfolio_sample
```

Ubuntu에서는 `fonts-nanum`을 설치하면 기존 한글 폰트 선택 경로를 사용할
수 있습니다. CI도 이 폰트를 준비합니다. 같은 폰트·라이브러리 환경의
반복 생성은 JSON/PDF 바이트가 같으며, 다른 폰트 환경에서는 PDF 페이지
수와 바이트 해시가 달라질 수 있습니다. JSON 내용은 플랫폼과 무관하게
재현됩니다.

입력은 생성 코드 내부의 고정 합성 자료뿐이며 실제 `logs/`, `evidence/`,
`reports/`를 읽지 않습니다. 실제 보고서·증적 디렉터리로의 샘플 출력은
거부합니다. 기존 공통 모델·순수 비교 모듈·PDF 렌더러를 재사용하며
프로덕션 진단 엔진은 실행하지 않습니다. 명시적인 합성 모드만 SAMPLE
표지·페이지 하단·본문·PDF 메타데이터를 표시합니다.
