"""Offline evaluation of observed security settings.

Raw observed values are kept out of model reprs. Repr is not a redaction or
serialization boundary. Never log observations/results via vars(), asdict(),
or a generic serializer. Use AuditResult.to_safe_dict() for logging and
export. It omits raw values, references and free-form metadata. The exported
identifiers must be opaque or otherwise non-secret. Keep credentials and raw
settings out of all metadata, including evidence references.

Collectors and rules should use the same canonical product ID, such as
"linux" or "mysql". Comparison ignores surrounding whitespace and case.
Aliases and unknown products are never mapped to other IDs. Use None when
the product is unidentified or a setting was not collected. Rule predicates
return None for inputs they cannot interpret; raised exceptions yield ERROR
without including exception text in the result.
"""
