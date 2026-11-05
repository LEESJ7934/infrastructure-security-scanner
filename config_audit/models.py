from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from .statuses import AuditStatus


@dataclass(frozen=True)
class AuditAsset:
    asset_id: str
    product: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class AuditRule:
    """Use a normalized product ID and a product-specific version predicate.

    Predicates are trusted local code. Return None when inputs cannot be
    interpreted reliably. An omitted condition requires manual judgment.
    Standards references are optional, caller-supplied, and should be verified
    against the applicable publication (for example, a KISA guide).
    """

    check_id: str
    rule_version: str
    expected_condition: str
    recommendation: str
    condition: Callable[[object], bool | None] | None = field(default=None, repr=False)
    product: str | None = None
    version_matches: Callable[[str], bool | None] | None = field(default=None, repr=False)
    standard_reference: str | None = None


@dataclass(frozen=True)
class Observation:
    """Use None for uncollected data, never a fabricated default.

    False, zero and an empty string may be actual observations. Each rule
    decides what those observed values mean.
    """

    observed_value: object = field(default=None, repr=False)
    evidence_reference: str | None = None
    collection_error: bool = False


@dataclass(frozen=True)
class AuditResult:
    asset_id: str
    product: str | None
    version: str | None
    check_id: str
    rule_version: str
    observed_value: object = field(repr=False)
    expected_condition: str
    status: AuditStatus
    evidence_reference: str | None
    recommendation: str
    execution_id: str
    checked_at: datetime
    previous_result_reference: str | None = None
    standard_reference: str | None = None

    def to_safe_dict(self) -> dict[str, str]:
        """Export status, time and non-secret identifiers for logging or sharing."""
        return {
            "asset_id": self.asset_id,
            "check_id": self.check_id,
            "rule_version": self.rule_version,
            "status": self.status.value,
            "execution_id": self.execution_id,
            "checked_at": self.checked_at.isoformat(),
        }
