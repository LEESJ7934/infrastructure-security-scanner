from typing import Protocol

from ..models import AuditAsset, Observation


class Collector(Protocol):
    """Future callers must enforce Scope and collection-specific authorization.

    Before any remote access, the caller must bind the asset to an approved
    endpoint and authorize the intended operation. This interface carries no
    authorization and grants no access.
    """

    def collect(self, asset: AuditAsset, check_id: str) -> Observation:
        """Return a minimal observation and a safe evidence reference."""
        ...
