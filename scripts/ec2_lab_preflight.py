"""Read-only AWS preflight for the user's EXISTING SSM-managed EC2 lab.

Never launches/stops an EC2, edits security groups or accesses public instance IP.
No credentials, profile names, environment variables or IAM keys are persisted.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys

LAB_PORTS = frozenset({2122, 2223, 8082, 4280})
INSTANCE_RE = re.compile(r"^i-[0-9a-f]{8}(?:[0-9a-f]{9})?$")
REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")


class EC2PreflightError(RuntimeError):
    pass


def check_instance_id(instance_id: str) -> str:
    if not INSTANCE_RE.fullmatch(instance_id):
        raise ValueError("Provide one exact existing EC2 instance ID")
    return instance_id


def aws_read(aws_cli: str, region: str, *command: str) -> dict:
    if not REGION_RE.fullmatch(region):
        raise ValueError("Invalid AWS region")
    try:
        done = subprocess.run(
            [aws_cli, *command, "--region", region, "--output", "json"],
            capture_output=True, text=True, check=True, timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        # AWS stderr may contain account identifiers or other credentials.
        raise EC2PreflightError("Read-only AWS CLI command failed: " + command[0]) from exc
    try:
        return json.loads(done.stdout)
    except (ValueError, TypeError) as exc:
        raise EC2PreflightError("AWS CLI response was not valid JSON") from exc


def rule_allows_public_lab_port(rule: dict) -> bool:
    protocol = str(rule.get("IpProtocol", ""))
    if protocol not in {"-1", "tcp", "6"}:
        return False
    if protocol != "-1":
        first, last = rule.get("FromPort"), rule.get("ToPort")
        if not isinstance(first, int) or not isinstance(last, int):
            return True   # uncertain: fail closed
        if not any(first <= port <= last for port in LAB_PORTS):
            return False
    cidrs = [p.get("CidrIp", "") for p in rule.get("IpRanges", [])]
    cidrs += [p.get("CidrIpv6", "") for p in rule.get("Ipv6Ranges", [])]
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr)
            if network.prefixlen == 0:  # full internet, either address family
                return True
        except ValueError:
            raise EC2PreflightError("Invalid CIDR in security-group ingress rule")
    return False


def inspect_existing_instance(*, instance_id: str, region: str,
                              aws_cli: str = "aws") -> dict:
    check_instance_id(instance_id)
    groups = aws_read(aws_cli, region, "ec2", "describe-instances",
                      "--instance-ids", instance_id)
    instances = [instance for reservation in groups.get("Reservations", [])
                 for instance in reservation.get("Instances", [])]
    if len(instances) != 1 or instances[0].get("InstanceId") != instance_id:
        raise EC2PreflightError("Exact EC2 instance could not be verified")
    instance = instances[0]
    if instance.get("State", {}).get("Name") != "running":
        raise EC2PreflightError("EC2 is not running")
    sg_ids = sorted({g.get("GroupId") for g in instance.get("SecurityGroups", [])
                     if g.get("GroupId")})
    if not sg_ids:
        raise EC2PreflightError("No EC2 security groups could be verified")
    sg = aws_read(aws_cli, region, "ec2", "describe-security-groups",
                  "--group-ids", *sg_ids)
    if {g["GroupId"] for g in sg.get("SecurityGroups", [])} != set(sg_ids):
        raise EC2PreflightError("Not all security group rules were inspected")
    if any(rule_allows_public_lab_port(rule)
           for group in sg["SecurityGroups"] for rule in group.get("IpPermissions", [])):
        raise EC2PreflightError("Public ingress permits at least one lab port; abort deployment")
    result = aws_read(aws_cli, region, "ssm", "describe-instance-information",
                      "--filters", f"Key=InstanceIds,Values={instance_id}")
    managed = [row for row in result.get("InstanceInformationList", [])
               if row.get("InstanceId") == instance_id]
    if len(managed) != 1 or managed[0].get("PingStatus") != "Online":
        raise EC2PreflightError("EC2 is not online via AWS Systems Manager")
    return {
        "instance_id": instance_id, "region": region, "instance_type": instance.get("InstanceType"),
        "ssm_status": "Online", "security_groups_checked": len(sg_ids),
        "lab_ports_bound_to_loopback_only": "REQUIRED",
        "resource_gate": "Run lab/ec2_resource_gate.sh on EC2 before deployment",
        "security_group_public_lab_ports": "DENIED",
        "aws_mutations_performed": False,
        "ec2_containers_deployed": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--aws-cli", default="aws")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(inspect_existing_instance(
            instance_id=args.instance_id, region=args.region, aws_cli=args.aws_cli),
            ensure_ascii=False, indent=2))
        return 0
    except (ValueError, EC2PreflightError) as exc:
        print(json.dumps({"status": "NOT_VERIFIED", "reason": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
