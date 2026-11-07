"""Synthetic network state and mocked Docker only; no daemons or packets."""
from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from config_audit.collectors import network_devices as net
from scripts.run_network_audit import main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lab_network_normalizer", ROOT / "lab/phase2-network/collect.py")
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)


def bundle():
    return {"schema_version":1,"origin":"synthetic","collected_at":"2026-11-06T00:00:00Z",
        "router":{"asset_id":"NET-LAB-ROUTER","product":"linux_frr","version":"10.2.2","sections":{
            "ssh":{"state":"COLLECTED","values":{"installed":False}},
            "listeners":{"state":"COLLECTED","values":{"tcp":[]}},
            "guard":{"state":"COLLECTED","values":{"input_policy":"drop","recognized_scope_only":True}},
            "logging":{"state":"COLLECTED","values":{"stdout_enabled":True}}}},
        "switch":{"asset_id":"NET-LAB-SWITCH","product":"docker_linux_bridge","version":"29.0.0","sections":{
            "bridge":{"state":"COLLECTED","values":{"driver_bridge":True,"internal":True,
                "expected_endpoints_only":True,"two_distinct_segments":True}}}}}


class NetworkAuditTests(unittest.TestCase):
    def rows(self, doc=None):
        return {row["check_id"]:row for row in net.audit(doc or bundle(),synthetic=True)["synthetic_results"]}

    def test_preparation_eight_not_tested(self):
        output=io.StringIO()
        with redirect_stdout(output): self.assertEqual(main([]),0)
        result=json.loads(output.getvalue())
        self.assertEqual(len(result["results"]),8)
        self.assertTrue(all(row["status"]=="NOT_TESTED" for row in result["results"]))

    def test_supported_checks_pass_and_unsupported_are_not_applicable(self):
        rows=self.rows()
        for check in ("NET-LAB-R02","NET-LAB-R03","NET-LAB-R04","NET-LAB-R05","NET-LAB-S03"):
            self.assertEqual(rows[check]["status"],"PASS")
        for check in ("NET-LAB-R01","NET-LAB-S01","NET-LAB-S02"):
            self.assertEqual(rows[check]["status"],"NOT_APPLICABLE")

    def test_two_synthetic_failures_then_pass(self):
        before=bundle()
        before["router"]["sections"]["guard"]["values"]["input_policy"]="accept"
        before["router"]["sections"]["listeners"]["values"]["tcp"]=[{"address":"0.0.0.0","port":8080}]
        for check in ("NET-LAB-R03","NET-LAB-R04"):
            self.assertEqual(self.rows(before)[check]["status"],"FAIL")
            self.assertEqual(self.rows()[check]["status"],"PASS")

    def test_missing_section_not_tested(self):
        doc=bundle(); del doc["router"]["sections"]["logging"]
        self.assertEqual(self.rows(doc)["NET-LAB-R05"]["status"],"NOT_TESTED")

    def test_linux_router_fallback_does_not_claim_active_frr_logging(self):
        doc=bundle();doc["router"].update(product="linux_router",version="6.6.87-microsoft-standard-WSL2")
        doc["router"]["sections"]["logging"]={"state":"NOT_TESTED","values":{}}
        rows=self.rows(doc)
        self.assertEqual(rows["NET-LAB-R05"]["status"],"NOT_TESTED")
        self.assertEqual(rows["NET-LAB-R03"]["status"],"PASS")

    def test_collection_failure_error(self):
        doc=bundle();doc["router"]["sections"]["logging"]={"state":"ERROR","error_code":"permission_denied"}
        self.assertEqual(self.rows(doc)["NET-LAB-R05"]["status"],"ERROR")

    def test_unknown_frr_version_needs_review(self):
        doc=bundle();doc["router"]["version"]=None
        self.assertEqual(self.rows(doc)["NET-LAB-R04"]["status"],"NEEDS_REVIEW")

    def test_telnet_and_vty_ipv4_ipv6_exposure(self):
        for address,port in (("0.0.0.0",23),("::",2601)):
            doc=bundle();doc["router"]["sections"]["listeners"]["values"]["tcp"]=[{"address":address,"port":port}]
            self.assertEqual(self.rows(doc)["NET-LAB-R02"]["status"],"FAIL")

    def test_loopback_vty_not_remote_telnet(self):
        doc=bundle();doc["router"]["sections"]["listeners"]["values"]["tcp"]=[{"address":"127.0.0.1","port":2601}]
        self.assertEqual(self.rows(doc)["NET-LAB-R02"]["status"],"PASS")

    def test_ssh_missing_values_review_not_pass(self):
        doc=bundle();doc["router"]["sections"]["ssh"]["values"]={"installed":True}
        self.assertEqual(self.rows(doc)["NET-LAB-R01"]["status"],"NEEDS_REVIEW")

    def test_ssh_secure_and_insecure(self):
        doc=bundle();values={"installed":True,"root_login_disabled":True,"password_login_disabled":True,"management_bind_only":True}
        doc["router"]["sections"]["ssh"]["values"]=values
        self.assertEqual(self.rows(doc)["NET-LAB-R01"]["status"],"PASS")
        values["password_login_disabled"]=False
        self.assertEqual(self.rows(doc)["NET-LAB-R01"]["status"],"FAIL")

    def test_unknown_filter_scope_not_pass(self):
        doc=bundle();doc["router"]["sections"]["guard"]["values"]["recognized_scope_only"]=False
        self.assertEqual(self.rows(doc)["NET-LAB-R03"]["status"],"NEEDS_REVIEW")

    def test_unexpected_virtual_endpoint_fails(self):
        doc=bundle();doc["switch"]["sections"]["bridge"]["values"]["expected_endpoints_only"]=False
        self.assertEqual(self.rows(doc)["NET-LAB-S03"]["status"],"FAIL")

    def test_no_vlan_pass_from_separate_bridges(self):
        self.assertEqual(self.rows()["NET-LAB-S02"]["status"],"NOT_APPLICABLE")

    def test_unknown_bridge_scope_not_pass(self):
        doc=bundle();doc["switch"]["sections"]["bridge"]["values"]["internal"]=False
        self.assertEqual(self.rows(doc)["NET-LAB-S03"]["status"],"NEEDS_REVIEW")

    def test_synthetic_channels_and_common_model(self):
        report=net.audit(bundle(),synthetic=True)
        self.assertEqual(report["results"],[])
        snapshot=net.to_report_snapshot(report,snapshot_id="network-synthetic")
        self.assertTrue(all(row.automatic is None for row in snapshot.results))
        self.assertEqual(report["packet_verification"]["status"],"NOT_TESTED")

    def test_common_engine_called_eight_times(self):
        with patch.object(net,"evaluate",wraps=net.evaluate) as evaluator:
            self.rows();self.assertEqual(evaluator.call_count,8)

    def test_synthetic_mode_must_be_explicit(self):
        with self.assertRaises(net.NetworkInputError):net.audit(bundle())

    def test_bad_shapes_secrets_and_vendor_rejected(self):
        for kind in ("secret","vendor","type"):
            doc=bundle()
            if kind=="secret":doc["api_secret"]="CANARY"
            if kind=="vendor":doc["router"]["product"]="cisco"
            if kind=="type":doc["router"]["sections"]["logging"]["values"]["stdout_enabled"]="true"
            with self.assertRaises(net.NetworkInputError) as error:net.validate(doc)
            self.assertNotIn("CANARY",str(error.exception))

    def test_invalid_json_missing_file_and_output_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"input.json"
            for raw in ("CANARY not json",'{"a":1,"a":2}'):
                path.write_text(raw)
                with self.assertRaises(net.NetworkInputError) as error:net.load_bundle(path)
                self.assertNotIn("CANARY",str(error.exception))
            path.unlink()
            with self.assertRaises(net.NetworkInputError):net.load_bundle(path)
            path.write_text(json.dumps(bundle()))
            output=Path(directory)/"out.json";output.write_text("PRESERVE")
            with redirect_stdout(io.StringIO()):self.assertEqual(main(["--input-json",str(path),"--synthetic","--output",str(output)]),2)
            self.assertEqual(output.read_text(),"PRESERVE")

    def test_normalize_socket_snapshot(self):
        actual=normalizer.listeners('LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\nLISTEN 0 128 [::1]:2601 [::]:*')
        self.assertEqual(actual["tcp"][1],{"address":"::1","port":2601})
        with self.assertRaises(ValueError):normalizer.listeners('unexpected')

    def guard(self):
        return {"nftables":[{"chain":{"family":"inet","table":"phase2_guard","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}}]}

    def test_normalize_owned_guard_and_unknown_accept_rule(self):
        data=self.guard()
        self.assertTrue(normalizer.guard(data)["recognized_scope_only"])
        data["nftables"].append({"rule":{"family":"inet","table":"phase2_guard","chain":"input","expr":[{"accept":None}]}})
        self.assertFalse(normalizer.guard(data)["recognized_scope_only"])

    def test_multiple_input_hooks_not_assumed_complete(self):
        data=self.guard();data["nftables"].append(deepcopy(data["nftables"][0]))
        self.assertIsNone(normalizer.guard(data)["input_policy"])

    def test_compose_isolation_contract(self):
        doc=json.loads((ROOT/"lab/phase2-network/compose.json").read_text())
        self.assertEqual(len(doc["services"]),3)
        for service in doc["services"].values():
            self.assertNotIn("ports",service);self.assertNotIn("volumes",service)
            self.assertFalse(service.get("privileged",False));self.assertNotIn("SYS_ADMIN",service["cap_add"])
            self.assertNotEqual(service.get("network_mode"),"host")
        self.assertTrue(all(net["internal"] for net in doc["networks"].values()))


class DockerScopeTests(unittest.TestCase):
    def response(self, command):
        if command==["docker","context","show"]:return "desktop-linux"
        if command[:3]==["docker","context","inspect"]:return json.dumps([{"Endpoints":{"docker":{"Host":self.endpoint}}}])
        args=command[3:]
        if args[:1]==["info"]:return "linux"
        if args[:1]==["inspect"]:
            name=args[1];service=name[len(net.PROJECT)+1:-2]
            data={"Id":service,"Config":{"Labels":{"com.docker.compose.project":net.PROJECT,"com.docker.compose.service":service}},
                  "State":{"Running":True},"HostConfig":{"Privileged":False,"PortBindings":{},"CapAdd":["NET_ADMIN"]},"Mounts":[]}
            data["NetworkSettings"]={"Networks":{net.PROJECT+"_"+name:{} for name in (("management","data_a","data_b") if service=="router" else ("data_a",) if service=="client-a" else ("data_b",))}}
            if self.modifier:self.modifier(data)
            return json.dumps([data])
        if args[:1]==["exec"]:
            if args[2:3]==["nft"]:return json.dumps(NetworkAuditTests().guard())
            return json.dumps(bundle()["router"])
        if args[:2]==["network","inspect"]:
            side=args[2][-1]
            endpoints={"router":{}} if args[2].endswith("management") else {"router":{},"client-"+side:{}}
            return json.dumps([{"Id":side,"Labels":{"com.docker.compose.project":net.PROJECT},"Driver":"bridge","Internal":True,"Containers":endpoints}])
        if args[:1]==["version"]:return "29.0.0"
        raise AssertionError("Unexpected command")

    def setUp(self):
        self.endpoint="npipe:////./pipe/dockerDesktopLinuxEngine";self.modifier=None

    def test_only_fixed_read_commands_and_owned_exec(self):
        with patch.object(net,"_run",side_effect=self.response) as query:
            actual=net.collect_docker()
        self.assertEqual(actual["origin"],"local_container_readonly")
        self.assertTrue(actual["switch"]["sections"]["bridge"]["values"]["expected_endpoints_only"])
        self.assertFalse(any(word in {"run","up","create","start","stop","rm"} for call in query.call_args_list for word in call.args[0]))

    def test_remote_endpoint_rejected_without_leaking_credentials(self):
        self.endpoint="tcp://user:CANARY@remote:2375"
        with patch.object(net,"_run",side_effect=self.response):
            with self.assertRaises(net.NetworkInputError) as error:net.collect_docker()
        self.assertNotIn("CANARY",str(error.exception))

    def test_foreign_container_rejected_before_exec(self):
        self.modifier=lambda data:data["Config"]["Labels"].update({"com.docker.compose.project":"other"})
        with patch.object(net,"_run",side_effect=self.response) as query:
            with self.assertRaises(net.NetworkInputError):net.collect_docker()
        self.assertFalse(any("exec" in call.args[0] for call in query.call_args_list))

    def test_privileged_mounts_and_published_ports_rejected(self):
        modifiers=[lambda d:d["HostConfig"].update(Privileged=True),lambda d:d.update(Mounts=[{}]),
                   lambda d:d["HostConfig"].update(PortBindings={"22/tcp":[{"HostPort":"22"}]}),
                   lambda d:d["HostConfig"].update(CapAdd=["SYS_ADMIN"])]
        for modifier in modifiers:
            self.modifier=modifier
            with patch.object(net,"_run",side_effect=self.response):
                with self.assertRaises(net.NetworkInputError):net.collect_docker()

    def test_docker_unavailable_not_success(self):
        with patch.object(net,"_run",side_effect=net.NetworkInputError("docker_unavailable")):
            with self.assertRaises(net.NetworkInputError):net.collect_docker()

    def test_additional_network_rejected_before_exec(self):
        self.modifier=lambda data:data["NetworkSettings"]["Networks"].update({"production":{}})
        with patch.object(net,"_run",side_effect=self.response) as query:
            with self.assertRaises(net.NetworkInputError):net.collect_docker()
        self.assertFalse(any("exec" in call.args[0] for call in query.call_args_list))


if __name__=="__main__":unittest.main()
