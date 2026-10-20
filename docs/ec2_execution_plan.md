# EC2 실측 실행 지침 — 기존 인스턴스만 사용

현재 ChatGPT에는 사용자 AWS SSM 실행 권한이 없습니다. 스크린샷에서 실행 중인 인스턴스와 다음 실제 실습 증명은 서로 다릅니다. 이 문서의 원격 명령은 **아직 실행되지 않았습니다**.

대상: test_server, i-036b5556c800856e0, 서울(ap-northeast-2), t3.micro. **퍼블릭 IPv4를 스캔하지 않습니다.**

## 1. PC에서 기존 EC2 안전성 확인

AWS CLI v2, Session Manager 플러그인, Python 3.12가 필요합니다. IAM 자격증명이나 SSH 키는 프로젝트·채팅에 올리지 않습니다. EC2의 SSM Agent가 Online이어야 하며 기존 인스턴스 IAM 역할/네트워크에 SSM 접속이 구성돼 있어야 합니다.

PowerShell:

    $env:AWS_LAB_INSTANCE_ID = "i-036b5556c800856e0"
    $env:AWS_DEFAULT_REGION = "ap-northeast-2"
    aws sts get-caller-identity
    python -m scripts.ec2_lab_preflight --instance-id $env:AWS_LAB_INSTANCE_ID --region $env:AWS_DEFAULT_REGION

실행기는 실행 상태, SSM Online, Security Group의 실습 포트 공개를 읽기 전용으로 확인합니다. SG/IAM/인스턴스 수정 없이 검사 실패시 중단합니다. **이것만으로 컨테이너가 배포됐다고 판단하지 않습니다.**

AWS 콘솔 EC2 → 대상 인스턴스 → 연결 → Session Manager에서 실제 셸 접속이 가능한지 확인합니다.

## 2. EC2 SSM 셸에서 배포 전 자원 검사

**t3.micro는 메모리 1GiB입니다.** DVWA/MariaDB를 포함한 여러 컨테이너를 동시에 시작하면 OOM/서비스 중단 가능성이 있습니다. 사전 게이트는 1.5GiB보다 작은 RAM이나 4GiB 미만의 기존 여유 디스크가 있으면 자동 배포를 막습니다. 추가 AWS 비용 또는 리소스 변경은 사전 승인 없이는 수행하지 않습니다.

EC2에서 사용자의 승인 후 GitHub 작업 브랜치를 내려받습니다.

    git clone --branch feat/controlled-lab-verification-20261020 https://github.com/LEESJ7934/infrastructure-security-scanner.git
    cd infrastructure-security-scanner
    bash lab/ec2_resource_gate.sh

이 명령은 기본적으로 읽기 전용입니다. Docker/Compose가 없다면 먼저 인스턴스 OS와 설치 방법을 확인해야 합니다. 설치와 EBS/인스턴스 증설은 자동 수행하지 않습니다.

**RAM/디스크 검사 통과 후**, 인스턴스 소유자가 명시적으로 승인한 경우에만 아래 명령을 실행합니다. 일회용 실습 자격정보는 셸 환경변수에만 두며 Git이나 채팅에 저장하지 않습니다.

    export AWS_LAB_INSTANCE_ID="i-036b5556c800856e0"
    export EC2_LAB_APPROVED="YES"
    export LAB_SSH_PASSWORD="$(openssl rand -hex 24)"
    export DVWA_DB_ROOT_PASSWORD="$(openssl rand -hex 24)"
    export DVWA_DB_PASSWORD="$(openssl rand -hex 24)"
    bash lab/ec2_resource_gate.sh --deploy

이 스크립트는 실제 IMDSv2 인스턴스 ID 확인, 가용 자원 점검, 모든 Docker 호스트 포트의 127.0.0.1 바인딩 확인 후 기존 Docker에서만 실습 서비스를 시작합니다. 운영 SSH, EC2 Security Group, IAM은 변경하지 않습니다. EC2 리사이즈도 하지 않습니다.

SSM 셸에서 실습 SSH 프로세스의 실제 인수를 확인합니다.

    docker compose -f lab/compose.yml exec -T ssh-weak sh -c "tr '\000' ' ' </proc/1/cmdline"

비밀번호 인증 사용 여부가 확인된 경우만 PC의 비공개 ssh_policy.local.json에 대응하는 127.0.0.1:2223 정책을 작성합니다. 운영 SSH와 혼동하지 마세요.

## 3. PC에서 로컬 정상 환경과 EC2 취약 환경 실제 비교

기존 MySQL의 V6 백업과 V7 적용을 먼저 완료합니다. PC 로컬 정상 서비스를 검사한 후 실제 로컬 스캔 ID를 기록합니다.

    python -m scripts.run_scan scan -sT -sV --target 127.0.0.1 --ports 2121,2222,8081 --scope-file config/scope.example.json --max-workers 4
    python -m scripts.run_lab_verification --scan-id LOCAL_SCAN_ID --scope-file config/scope.example.json --environment LOCAL_BASELINE --allow-ftp-anonymous

정상 환경 서비스가 없다면 NOT_TESTED이며 안전 판정이 아닙니다. EC2 쪽 실습 포트(2122,2223,8082,4280)는 사용자 PC의 동일 포트로 **SSM 터널링**됩니다. 기존 운영 SSH(22)와 공개 IP를 스캔하지 않습니다.

PC의 검증된 Nuclei 바이너리 및 별도 DVWA 실습 계정 환경변수를 준비한 후 PowerShell에서 실행합니다. 비밀번호를 명령줄에 적거나 Git에 저장하지 않습니다.

    python -m scripts.ec2_lab_tunnel_run --instance-id i-036b5556c800856e0 --region ap-northeast-2 --phase before --baseline-scan-id LOCAL_SCAN_ID --scope-file config/scope.example.json --nuclei-binary APPROVED_NUCLEI_PATH --ssh-policy-file ssh_policy.local.json --execute

실행기는 EC2와 SSM Online, 위험한 SG 공개 설정, 포트 충돌을 먼저 검사하고, 원격 서비스 스캔 → FTP·SSH·HTTP → DVWA·Nuclei → MySQL 증적 → JSON/PDF와 SSM 실행 manifest 저장을 처리합니다. 실제 실행이 실패한 항목은 CONFIRMED 처리하지 않습니다.

**중요:** SSM 터널을 통해 PC의 127.0.0.1로 전송하는 방식은 포트 검사 및 애플리케이션 결과를 입증하지만, 그 자체로 AWS 인스턴스 구성의 진정성을 암호학적으로 입증하지는 않습니다. manifest의 연결 방법, 실행 시각과 스캔 ID를 함께 검토해야 합니다.

## 4. EC2 실습 HTTP 서비스 개선 후 재점검

위 실측 성공 이후 EC2 SSM 셸에서 소유자가 승인하여 **실습 HTTP 컨테이너만** 개선 설정으로 재생성합니다.

    docker compose -f lab/compose.yml -f lab/compose.retest.yml --profile vulnerable up -d --no-deps --force-recreate http-weak

PC에서는 위 실측에서 발급된 원래 EC2 scan ID를 지정합니다.

    python -m scripts.ec2_lab_tunnel_run --instance-id i-036b5556c800856e0 --region ap-northeast-2 --phase after --baseline-scan-id LOCAL_SCAN_ID --ec2-scan-id EC2_SCAN_ID --scope-file config/scope.example.json --execute

같은 포트의 헤더 상태가 실제 POTENTIAL → NOT_DETECTED가 된 경우에만 MySQL V7과 비교 보고서에 새 증적을 기록합니다. 운영 환경이나 다른 취약점의 개선을 뜻하지 않습니다.

## 5. 실측 결과 검토 및 포트폴리오 반영

PC의 reports/ec2 폴더에 생성된 JSON, PDF, SSM before/after manifest의 실행 시점, SHA-256, scan ID를 검토합니다. 보안 증적은 인증정보·세션 쿠키가 없는 범위에서만 공개합니다. 실제 EC2 적용 로그가 확보되기 전까지 GitHub/노션의 기존 **Docker CI 검증 성공** 항목과 **EC2 실측 미검증** 문구를 바꾸지 않습니다.

프로젝트의 Docker CI 통과 기록: https://github.com/LEESJ7934/infrastructure-security-scanner/actions/runs/39416258614

현재 미확인: AWS SSM 연결 상태, EC2 OS와 Docker 설치, 디스크 여유, 실제 EC2 취약 서비스 배포, SQLi 실측, 재점검. 인스턴스 상태 스크린샷만으로는 이 항목을 완료 처리할 수 없습니다.
