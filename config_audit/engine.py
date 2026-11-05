from datetime import datetime

from .models import AuditAsset, AuditResult, AuditRule, Observation
from .statuses import AuditStatus


def _applicable(asset: AuditAsset, rule: AuditRule) -> bool | None:
    if rule.product is not None:
        asset_product = (asset.product or "").strip().casefold()
        rule_product = rule.product.strip().casefold()
        if not asset_product or not rule_product:
            return None
        if asset_product != rule_product:
            return False
    if rule.version_matches is None:
        return True
    version = (asset.version or "").strip()
    if not version:
        return None
    return rule.version_matches(version)


def _status(asset: AuditAsset, rule: AuditRule, observation: Observation) -> AuditStatus:
    # Collection failures take precedence, even for out-of-scope products.
    if observation.collection_error:
        return AuditStatus.ERROR
    try:
        applicable = _applicable(asset, rule)
    except Exception:
        return AuditStatus.ERROR
    if applicable is False:
        return AuditStatus.NOT_APPLICABLE
    if applicable is not True:
        return AuditStatus.NEEDS_REVIEW
    if observation.observed_value is None:
        return AuditStatus.NOT_TESTED
    if rule.condition is not None:
        try:
            satisfied = rule.condition(observation.observed_value)
        except Exception:
            return AuditStatus.ERROR
        if satisfied is True:
            return AuditStatus.PASS
        if satisfied is False:
            return AuditStatus.FAIL
    return AuditStatus.NEEDS_REVIEW


def evaluate(
    asset: AuditAsset,
    rule: AuditRule,
    observation: Observation,
    *,
    execution_id: str,
    checked_at: datetime,
    previous_result_reference: str | None = None,
) -> AuditResult:
    """Evaluate supplied data with local predicates, without running a collector."""
    return AuditResult(
        asset_id=asset.asset_id,
        product=asset.product,
        version=asset.version,
        check_id=rule.check_id,
        rule_version=rule.rule_version,
        observed_value=observation.observed_value,
        expected_condition=rule.expected_condition,
        status=_status(asset, rule, observation),
        evidence_reference=observation.evidence_reference,
        recommendation=rule.recommendation,
        execution_id=execution_id,
        checked_at=checked_at,
        previous_result_reference=previous_result_reference,
        standard_reference=rule.standard_reference,
    )
