from dataclasses import replace
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import Mock

from config_audit.engine import evaluate
from config_audit.models import AuditAsset, AuditRule, Observation
from config_audit.statuses import AuditStatus


class ConfigAuditTests(unittest.TestCase):
    def setUp(self):
        self.asset = AuditAsset("asset-1", "mysql", "8.0.40")
        self.rule = AuditRule(
            check_id="example:local-infile",
            rule_version="1",
            expected_condition="local_infile is disabled",
            recommendation="Disable local_infile when it is not required.",
            condition=lambda value: not value if isinstance(value, bool) else None,
        )
        self.checked_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def evaluate(self, observation, *, asset=None, rule=None, previous_result_reference=None):
        return evaluate(
            asset or self.asset,
            rule or self.rule,
            observation,
            execution_id="run-2",
            checked_at=self.checked_at,
            previous_result_reference=previous_result_reference,
        )

    def test_disabled_setting_passes_with_observed_false(self):
        self.assertEqual(self.evaluate(Observation(False)).status, AuditStatus.PASS)

    def test_enabled_setting_fails(self):
        self.assertEqual(self.evaluate(Observation(True)).status, AuditStatus.FAIL)

    def test_missing_observation_cannot_pass_even_with_evidence_reference(self):
        condition = Mock(return_value=True)
        rule = replace(self.rule, condition=condition)
        result = self.evaluate(Observation(evidence_reference="evidence-1"), rule=rule)
        self.assertEqual(result.status, AuditStatus.NOT_TESTED)
        condition.assert_not_called()

    def test_manual_or_inconclusive_rule_needs_review(self):
        cases = (
            (Observation(False), replace(self.rule, condition=None)),
            (Observation("unknown"), self.rule),
        )
        for observation, rule in cases:
            with self.subTest(observation=observation):
                self.assertEqual(self.evaluate(observation, rule=rule).status, AuditStatus.NEEDS_REVIEW)

    def test_collection_error_is_not_a_verdict_even_with_partial_value(self):
        result = self.evaluate(Observation(False, collection_error=True))
        self.assertEqual(result.status, AuditStatus.ERROR)

    def test_product_and_version_applicability(self):
        rule = replace(self.rule, product="mysql", version_matches=lambda version: version.startswith("8."))
        cases = (
            (self.asset, AuditStatus.PASS),
            (replace(self.asset, product="postgresql"), AuditStatus.NOT_APPLICABLE),
            (replace(self.asset, version="5.7.44"), AuditStatus.NOT_APPLICABLE),
            (replace(self.asset, product=None), AuditStatus.NEEDS_REVIEW),
            (replace(self.asset, version=None), AuditStatus.NEEDS_REVIEW),
        )
        for asset, expected in cases:
            with self.subTest(asset=asset):
                self.assertEqual(self.evaluate(Observation(False), asset=asset, rule=rule).status, expected)

    def test_unknown_version_applicability_needs_review(self):
        rule = replace(self.rule, version_matches=lambda version: None)
        self.assertEqual(self.evaluate(Observation(False), rule=rule).status, AuditStatus.NEEDS_REVIEW)

    def test_retest_retains_previous_result_and_evidence_references(self):
        result = self.evaluate(
            Observation(False, evidence_reference="evidence-2"),
            previous_result_reference="result-1",
        )
        self.assertEqual(result.previous_result_reference, "result-1")
        self.assertEqual(result.evidence_reference, "evidence-2")
        self.assertEqual(result.execution_id, "run-2")
        self.assertEqual(result.checked_at, self.checked_at)
        self.assertEqual(result.asset_id, self.asset.asset_id)
        self.assertEqual(result.check_id, self.rule.check_id)
        self.assertEqual(result.rule_version, self.rule.rule_version)

    def test_model_repr_omits_observed_value(self):
        observation = Observation("sensitive-fixture")
        self.assertNotIn("sensitive-fixture", repr(observation))
        self.assertNotIn("sensitive-fixture", repr(self.evaluate(observation)))

    def test_version_predicate_exception_returns_error(self):
        version_matches = Mock(side_effect=ValueError("sensitive-version-fixture"))
        condition = Mock(return_value=True)
        rule = replace(self.rule, version_matches=version_matches, condition=condition)

        result = self.evaluate(Observation(False), rule=rule)

        self.assertEqual(result.status, AuditStatus.ERROR)
        version_matches.assert_called_once_with(self.asset.version)
        condition.assert_not_called()
        self.assertNotIn("sensitive-version-fixture", repr(result))

    def test_condition_exception_returns_error_without_exception_text(self):
        condition = Mock(side_effect=RuntimeError("sensitive-setting-fixture"))
        result = self.evaluate(Observation(False), rule=replace(self.rule, condition=condition))

        self.assertEqual(result.status, AuditStatus.ERROR)
        condition.assert_called_once_with(False)
        self.assertNotIn("sensitive-setting-fixture", repr(result))

    def test_collection_error_precedes_version_predicate_that_would_raise(self):
        version_matches = Mock(side_effect=ValueError("unusable version"))
        rule = replace(self.rule, version_matches=version_matches)
        result = self.evaluate(Observation(collection_error=True), rule=rule)

        self.assertEqual(result.status, AuditStatus.ERROR)
        version_matches.assert_not_called()

    def test_collection_error_precedes_explicit_product_exclusion(self):
        rule = replace(self.rule, product="postgresql")
        result = self.evaluate(Observation(False, collection_error=True), rule=rule)
        self.assertEqual(result.status, AuditStatus.ERROR)

    def test_product_comparison_ignores_case_and_surrounding_whitespace(self):
        asset = replace(self.asset, product=" MySQL ")
        rule = replace(self.rule, product="mysql")
        self.assertEqual(self.evaluate(Observation(False), asset=asset, rule=rule).status, AuditStatus.PASS)

    def test_missing_or_whitespace_product_needs_review_for_product_rule(self):
        rule = replace(self.rule, product="mysql")
        for product in (None, "", "  "):
            with self.subTest(product=product):
                asset = replace(self.asset, product=product)
                self.assertEqual(self.evaluate(Observation(False), asset=asset, rule=rule).status,
                                 AuditStatus.NEEDS_REVIEW)

    def test_uninterpretable_version_needs_review(self):
        version_matches = Mock(return_value=None)
        rule = replace(self.rule, version_matches=version_matches)
        asset = replace(self.asset, version="uninterpretable")

        self.assertEqual(self.evaluate(Observation(False), asset=asset, rule=rule).status,
                         AuditStatus.NEEDS_REVIEW)
        version_matches.assert_called_once_with("uninterpretable")

    def test_zero_and_empty_string_are_evaluated_without_defaulting_missing_data(self):
        for value in (0, ""):
            with self.subTest(value=value):
                condition = Mock(return_value=True)
                rule = replace(self.rule, condition=condition)
                self.assertEqual(self.evaluate(Observation(None), rule=rule).status, AuditStatus.NOT_TESTED)
                condition.assert_not_called()
                self.assertEqual(self.evaluate(Observation(value), rule=rule).status, AuditStatus.PASS)
                condition.assert_called_once_with(value)

    def test_safe_serialization_only_exports_allowlisted_fields(self):
        secret = "sensitive-setting-fixture"
        rule = replace(self.rule, recommendation=secret)
        result = self.evaluate(
            Observation(secret, evidence_reference=secret),
            rule=rule,
            previous_result_reference=secret,
        )

        exported = result.to_safe_dict()
        self.assertEqual(exported, {
            "asset_id": self.asset.asset_id,
            "check_id": self.rule.check_id,
            "rule_version": self.rule.rule_version,
            "status": "NEEDS_REVIEW",
            "execution_id": "run-2",
            "checked_at": self.checked_at.isoformat(),
        })
        self.assertNotIn(secret, json.dumps(exported))
