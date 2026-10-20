"""Offline tests: AWS/SSM are always mocked; no account or instance contacted."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.ec2_lab_preflight import (
    EC2PreflightError, inspect_existing_instance, rule_allows_public_lab_port,
)
from scripts.ec2_lab_tunnel_run import _local_port_free, _verified_scope, _write_manifest, ssm_tunnels


INSTANCE = "i-036b5556c800856e0"
REGION = "ap-northeast-2"


class PreflightTests(unittest.TestCase):
    def test_security_group_public_lab_ports_deny_both_families(self):
        for rule in (
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 2122, "ToPort": 2122,
             "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
            {"IpProtocol": "6", "FromPort": 2000, "ToPort": 9000,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ):
            with self.subTest(rule=rule):
                self.assertTrue(rule_allows_public_lab_port(rule))
        self.assertFalse(rule_allows_public_lab_port({
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}))
        self.assertFalse(rule_allows_public_lab_port({
            "IpProtocol": "tcp", "FromPort": 4280, "ToPort": 4280,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}))

    @patch("scripts.ec2_lab_preflight.aws_read")
    def test_existing_running_ssm_instance_read_only(self, aws):
        aws.side_effect = [
            {"Reservations": [{"Instances": [{
                "InstanceId": INSTANCE, "State": {"Name": "running"},
                "InstanceType": "t3.micro",
                "SecurityGroups": [{"GroupId": "sg-abc123"}]}]}]},
            {"SecurityGroups": [{"GroupId": "sg-abc123",
                                 "IpPermissions": [{"IpProtocol": "tcp",
                                                    "FromPort": 22, "ToPort": 22,
                                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]},
            {"InstanceInformationList": [{"InstanceId": INSTANCE, "PingStatus": "Online"}]},
        ]
        output = inspect_existing_instance(instance_id=INSTANCE, region=REGION)
        self.assertEqual(output["ssm_status"], "Online")
        self.assertFalse(output["aws_mutations_performed"])
        self.assertFalse(output["ec2_containers_deployed"])
        self.assertEqual(aws.call_count, 3)
        self.assertEqual([x.args[2] for x in aws.call_args_list],
                         ["ec2", "ec2", "ssm"])

    @patch("scripts.ec2_lab_preflight.aws_read")
    def test_offline_ssm_aborts(self, aws):
        aws.side_effect = [
            {"Reservations": [{"Instances": [{"InstanceId": INSTANCE,
                "State": {"Name": "running"}, "SecurityGroups": [{"GroupId": "sg-1"}]}]}]},
            {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": []}]},
            {"InstanceInformationList": [{"InstanceId": INSTANCE, "PingStatus": "ConnectionLost"}]},
        ]
        with self.assertRaises(EC2PreflightError):
            inspect_existing_instance(instance_id=INSTANCE, region=REGION)

    @patch("scripts.ec2_lab_preflight.aws_read")
    def test_unsafe_security_group_aborts_before_ssm(self, aws):
        aws.side_effect = [
            {"Reservations": [{"Instances": [{"InstanceId": INSTANCE,
                "State": {"Name": "running"}, "SecurityGroups": [{"GroupId": "sg-1"}]}]}]},
            {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [{
                "IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}]},
        ]
        with self.assertRaises(EC2PreflightError):
            inspect_existing_instance(instance_id=INSTANCE, region=REGION)
        self.assertEqual(aws.call_count, 2)


class TunnelTests(unittest.TestCase):
    @patch("scripts.ec2_lab_tunnel_run._local_port_free", return_value=False)
    @patch("scripts.ec2_lab_tunnel_run.subprocess.Popen")
    def test_local_port_collision_aborts_without_ssm(self, process, free):
        with self.assertRaises(RuntimeError):
            with ssm_tunnels(instance_id=INSTANCE, region=REGION, ports=(8082,)):
                pass
        process.assert_not_called()

    def test_broad_scope_denied(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "scope.json"
            file.write_text(json.dumps({
                "scope_uid": "test", "name": "test", "authorization_ref": "owner",
                "approved_by": "owner", "valid_from": "2020-01-01T00:00:00+00:00",
                "valid_until": "2090-01-01T00:00:00+00:00",
                "allowed_targets": ["0.0.0.0/0"], "max_targets": 4,
                "max_workers": 4, "max_ports_per_target": 4,
            }))
            with self.assertRaises(ValueError):
                _verified_scope(file)

    def test_manifest_is_a_hash_of_actual_run_content(self):
        with tempfile.TemporaryDirectory() as d:
            file = _write_manifest(
                output_dir=Path(d), instance_id=INSTANCE, region=REGION,
                local_id=2, ec2_id=4, phase="before", results=[{"finding_status":"CONFIRMED"}],
                report={"json_path":"reports/lab.json"})
            data = json.loads(Path(file).read_text(encoding="utf-8"))
            digest = data.pop("manifest_sha256")
            encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            self.assertEqual(digest, hashlib.sha256(encoded.encode()).hexdigest())
            self.assertFalse(data["aws_resource_changes"] != "NONE_BY_RUNNER")


if __name__ == "__main__":
    unittest.main()
