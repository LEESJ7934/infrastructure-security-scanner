#!/usr/bin/env bash
# Owner-operated on the existing EC2 using SSM. Read-only by default.
set -euo pipefail
set +x

if [ "$#" -eq 0 ] || [ "$1" != "--deploy" ]; then
  echo "Read-only EC2 resource check:"
  awk '/MemTotal:/{print "memory_kib="$2}' /proc/meminfo
  df -Pk . | tail -n 1 | awk '{print "disk_free_kib="$4}'
  command -v docker >/dev/null && docker --version || echo "Docker is not installed"
  docker compose version 2>/dev/null || echo "Docker Compose not installed"
  echo "Deployment requires an explicit owner opt-in, and does not modify host SSH or AWS settings."
  exit 0
fi
if [ "${EC2_LAB_APPROVED:-}" != "YES" ] || [ -z "${AWS_LAB_INSTANCE_ID:-}" ]; then
  echo "Explicit approval and existing EC2 instance ID required" >&2; exit 2
fi
if ! [[ "$AWS_LAB_INSTANCE_ID" =~ ^i-[0-9a-f]{8}([0-9a-f]{9})?$ ]]; then
  echo "Invalid EC2 instance ID" >&2; exit 2
fi

# Fail closed unless IMDSv2 proves this is the selected existing instance.
command -v curl >/dev/null || { echo "curl required for IMDSv2" >&2; exit 2; }
token="$(curl -fsS --noproxy '*' --connect-timeout 2 --max-time 4 \
  -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
  http://169.254.169.254/latest/api/token)" || {
    echo "EC2 IMDSv2 unavailable; deployment refused" >&2; exit 2;
  }
observed_id="$(curl -fsS --noproxy '*' --connect-timeout 2 --max-time 4 \
  -H "X-aws-ec2-metadata-token: $token" \
  http://169.254.169.254/latest/meta-data/instance-id)" || exit 2
unset token
[ "$observed_id" = "$AWS_LAB_INSTANCE_ID" ] || {
  echo "Wrong EC2 instance; deployment refused" >&2; exit 2;
}

command -v docker >/dev/null && docker compose version >/dev/null || {
  echo "Docker/Compose installation needed; no automatic OS changes" >&2; exit 3;
}
free_kib="$(df -Pk . | tail -n1 | awk '{print $4}')"
memory_kib="$(awk '/MemTotal:/{print $2}' /proc/meminfo)"
[ "$free_kib" -ge 4194304 ] || {
  echo "Require 4 GiB already-free disk; refusing EBS changes" >&2; exit 3;
}
if [ "$memory_kib" -lt 1572864 ] && [ "${EC2_LAB_ALLOW_LOW_MEMORY:-}" != "YES" ]; then
  echo "Less than 1.5 GiB RAM; user approval required for OOM risk" >&2
  echo "No EC2 resize or swap creation is performed" >&2
  exit 3
fi
for secret in LAB_SSH_PASSWORD DVWA_DB_ROOT_PASSWORD DVWA_DB_PASSWORD; do
  if [ -z "$(printenv "$secret" 2>/dev/null || true)" ]; then
    echo "Missing ephemeral environment secret: $secret" >&2; exit 2
  fi
done

# Inspect computed configuration without displaying secret-bearing JSON.
docker compose -f lab/compose.yml --profile vulnerable config --format json \
  | python3 -c '
import json,sys
for name,service in json.load(sys.stdin)["services"].items():
    for port in service.get("ports",[]):
        if port.get("host_ip") != "127.0.0.1":
            raise SystemExit("Refusing non-loopback bind: "+name)
print("All exposed lab ports are bound to 127.0.0.1")
'
docker compose -f lab/compose.yml --profile vulnerable up -d --build
docker compose -f lab/compose.yml --profile vulnerable ps
echo "Docker deployment command completed; live vulnerability proof remains a separate step."
