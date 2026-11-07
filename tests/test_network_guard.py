"""R03 JSON normalization regressions; synthetic data, no Docker or rules writes."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import test_network_audit as fixtures
from config_audit.collectors import network_devices as net
from scripts.run_network_audit import main


def chain_document(states=None):
    base={"family":"inet","table":"phase2_guard","chain":"input"}
    matches=[{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"},
             {"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"] if states is None else states},
             {"op":"==","left":{"meta":{"key":"l4proto"}},"right":"icmp"}]
    return {"nftables":[{"metainfo":{"json_schema_version":1}},
        {"chain":{"family":"inet","table":"phase2_guard","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},
        *[{"rule":{**base,"expr":[{"match":match},{"accept":None}]}} for match in matches]]}


class GuardParserTests(unittest.TestCase):
    def test_actual_form_plain_ct_state_array_is_recognized(self):
        result=net.normalize_guard(chain_document())
        self.assertTrue(result["recognized_scope_only"])
        self.assertEqual(result["recognized_exceptions"],["established_related","icmp","loopback"])
        self.assertEqual(result["unrecognized_reason_codes"],[])

    def test_set_wrapper_and_order_are_semantically_equivalent(self):
        for states in (["related","established"],{"set":["established","related"]}):
            self.assertTrue(net.normalize_guard(chain_document(states))["recognized_scope_only"])

    def test_new_state_cannot_be_allowed_as_established(self):
        result=net.normalize_guard(chain_document(["established","related","new"]))
        self.assertFalse(result["recognized_scope_only"])
        self.assertTrue(result["disallowed_accept"])

    def test_negative_match_operator_cannot_be_whitelisted(self):
        doc=chain_document();doc["nftables"][2]["rule"]["expr"][0]["match"]["op"]="!="
        self.assertFalse(net.normalize_guard(doc)["recognized_scope_only"])

    def test_numeric_icmp_only_not_tcp_ipv6_or_boolean(self):
        for protocol,allowed in ((1,True),(6,False),(58,False),(True,False)):
            doc=chain_document();doc["nftables"][4]["rule"]["expr"][0]["match"]["right"]=protocol
            self.assertEqual(net.normalize_guard(doc)["recognized_scope_only"],allowed)

    def test_counter_metadata_does_not_change_rule_semantics(self):
        doc=chain_document()
        for row in doc["nftables"][2:]:row["rule"]["expr"].insert(1,{"counter":{"packets":12,"bytes":1000}})
        self.assertTrue(net.normalize_guard(doc)["recognized_scope_only"])

    def test_unconditional_extra_accept_is_fail(self):
        doc=chain_document();doc["nftables"].append({"rule":{"family":"inet","table":"phase2_guard","chain":"input","expr":[{"accept":None}]}})
        values=net.normalize_guard(doc)
        self.assertTrue(values["disallowed_accept"])
        self.assertFalse(net.satisfied("NET-LAB-R03",values))

    def test_extra_tcp_accept_is_not_approved(self):
        doc=chain_document();rule=deepcopy(doc["nftables"][2])
        rule["rule"]["expr"][0]={"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}}
        doc["nftables"].append(rule)
        self.assertFalse(net.normalize_guard(doc)["recognized_scope_only"])

    def test_unknown_jump_stays_review(self):
        doc=chain_document();doc["nftables"].append({"rule":{"family":"inet","table":"phase2_guard","chain":"input","expr":[{"jump":{"target":"other"}}]}})
        values=net.normalize_guard(doc)
        self.assertFalse(values["recognized_scope_only"])
        self.assertIsNone(net.satisfied("NET-LAB-R03",values))

    def test_docker_nat_and_foreign_hooks_are_out_of_scope(self):
        doc=chain_document()
        doc["nftables"] += [
            {"table":{"family":"ip","name":"nat"}},
            {"chain":{"family":"ip","table":"nat","name":"OUTPUT","hook":"output","type":"nat","policy":"accept"}},
            {"chain":{"family":"ip","table":"docker","name":"INPUT","hook":"input","type":"filter","policy":"accept"}},
            {"rule":{"family":"ip","table":"nat","chain":"OUTPUT","expr":[{"dnat":{"addr":"127.0.0.11"}}]}}]
        self.assertTrue(net.normalize_guard(doc)["recognized_scope_only"])

    def test_wrong_table_or_duplicate_owned_chain_not_pass(self):
        for duplicate in (False,True):
            doc=chain_document()
            if duplicate:doc["nftables"].append(deepcopy(doc["nftables"][1]))
            else:doc["nftables"][1]["chain"]["table"]="foreign"
            self.assertIsNone(net.normalize_guard(doc)["input_policy"])

    def test_missing_hook_priority_or_invalid_metadata_not_pass(self):
        for field in ("hook","prio","type"):
            doc=chain_document();del doc["nftables"][1]["chain"][field]
            self.assertFalse(net.normalize_guard(doc)["recognized_scope_only"])

    def test_explicit_dormant_table_not_pass(self):
        doc=chain_document();doc["nftables"].append({"table":{"family":"inet","name":"phase2_guard","flags":["dormant"]}})
        self.assertFalse(net.normalize_guard(doc)["recognized_scope_only"])

    def test_rule_comments_never_exported(self):
        doc=chain_document();doc["nftables"][2]["rule"]["comment"]="CANARY_SECRET"
        self.assertNotIn("CANARY_SECRET",json.dumps(net.normalize_guard(doc)))


class GuardRetestTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        before=fixtures.bundle();before["origin"]="local_container_readonly"
        before["router"]["sections"]["guard"]["values"].update(input_policy="accept",recognized_scope_only=False)
        before["router"]["sections"]["listeners"]["values"]["tcp"]=[{"address":"0.0.0.0","port":8080}]
        saved=net.audit(before)
        next(row for row in saved["results"] if row["check_id"]=="NET-LAB-R03")["rule_version"]="NET-LAB-0.1"
        self.before=self.root/"before.json";self.before.write_text(json.dumps(saved),encoding="utf-8")
        after=fixtures.bundle();after["origin"]="local_container_readonly"
        after["router"]["sections"]["guard"]["values"]["recognized_scope_only"]=False
        self.after=self.root/"after.json";self.after.write_text(json.dumps(net.audit(after)),encoding="utf-8")
        self.guard=self.root/"guard.json";self.guard.write_text(json.dumps(chain_document()),encoding="utf-8-sig")

    def result(self):
        bundle=net.load_bundle(self.after)[0]
        updated,source=net.apply_guard_export(bundle,self.guard)
        result=net.audit(updated);result["supplemental_guard_evidence"]=source
        return net.attach_baseline(result,self.before)

    def test_real_format_retest_links_two_improvements(self):
        result=self.result()
        self.assertEqual(result["baseline_comparison"]["summary"]["IMPROVED_OBSERVED"],2)
        r03=next(row for row in result["results"] if row["check_id"]=="NET-LAB-R03")
        self.assertEqual(r03["status"],"PASS")
        self.assertEqual(r03["verification_method"],"offline_user_exported_nft_chain")
        self.assertIsNone(r03["collected_at"])

    def test_originals_and_original_guard_preserved(self):
        before,after=self.before.read_bytes(),self.after.read_bytes()
        result=self.result()
        self.assertEqual(self.before.read_bytes(),before);self.assertEqual(self.after.read_bytes(),after)
        self.assertFalse(result["supplemental_guard_evidence"]["original_guard"]["values"]["recognized_scope_only"])

    def test_legacy_snapshot_is_not_silently_upgraded_without_raw_chain(self):
        doc=net.load_bundle(self.after)[0]
        self.assertEqual(next(row for row in net.audit(doc)["results"] if row["check_id"]=="NET-LAB-R03")["status"],"NEEDS_REVIEW")

    def test_cli_after_v2_no_overwrite_and_reused_sources_labeled(self):
        target=self.root/"after-v2.json"
        args=["--input-json",str(self.after),"--guard-json",str(self.guard),"--baseline-json",str(self.before),"--output",str(target)]
        with redirect_stdout(io.StringIO()):self.assertEqual(main(args),0)
        report=json.loads(target.read_text())
        self.assertEqual(report["mode"],"LAB_OFFLINE_GUARD_RETEST")
        self.assertEqual(next(row for row in report["results"] if row["check_id"]=="NET-LAB-R04")["verification_method"],"saved_after_json_reused")
        raw=target.read_bytes()
        with redirect_stdout(io.StringIO()):self.assertEqual(main(args),2)
        self.assertEqual(target.read_bytes(),raw)

    def test_baseline_duplicate_and_asset_mismatch_not_selected_arbitrarily(self):
        data=json.loads(self.before.read_text());data["results"].append(data["results"][0])
        self.before.write_text(json.dumps(data))
        with self.assertRaises(net.NetworkInputError):self.result()
        data["results"].pop();data["bundle"]["router"]["asset_id"]="NET-LAB-OTHER"
        self.before.write_text(json.dumps(data))
        result=self.result()
        self.assertTrue(all(row["comparison_result"]=="INCOMPARABLE" for row in result["baseline_comparison"]["results"] if row["check_id"].startswith("NET-LAB-R")))

    def test_malformed_export_no_pass(self):
        self.guard.write_text('CANARY not json')
        with self.assertRaises(net.NetworkInputError) as error:self.result()
        self.assertNotIn("CANARY",str(error.exception))


class HostNormalizerTests(unittest.TestCase):
    setUp = fixtures.DockerScopeTests.setUp
    def response(self, command):
        if command[3:6]==["exec",net.PROJECT+"-router-1","nft"]:
            if getattr(self,"fail_chain",False):raise net.NetworkInputError("docker_query_failed")
            return json.dumps(chain_document())
        return fixtures.DockerScopeTests.response(self, command)

    def test_old_container_normalizer_is_replaced_without_rebuild(self):
        with patch.object(net,"_run",side_effect=self.response) as calls:
            result=net.audit(net.collect_docker())
        r03=next(row for row in result["results"] if row["check_id"]=="NET-LAB-R03")
        self.assertEqual(r03["status"],"PASS")
        self.assertTrue(any(call.args[0][-7:]==["nft","-j","list","chain","inet","phase2_guard","input"] for call in calls.call_args_list))
        self.assertFalse(any(word in {"cp","up","restart","build","flush","delete","add"} for call in calls.call_args_list for word in call.args[0]))

    def test_target_chain_query_failure_independent_from_other_checks(self):
        self.fail_chain=True
        with patch.object(net,"_run",side_effect=self.response):result=net.audit(net.collect_docker())
        rows={row["check_id"]:row for row in result["results"]}
        self.assertEqual(rows["NET-LAB-R03"]["status"],"ERROR")
        self.assertEqual(rows["NET-LAB-R04"]["status"],"PASS")


if __name__=="__main__":unittest.main()
