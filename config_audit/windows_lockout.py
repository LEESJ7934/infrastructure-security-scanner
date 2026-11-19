"""Shared KISA-selected lockout predicates; not an organization policy.

The guide's numeric duration recommendation and effective enablement are
reported separately. Zero duration (manual unlock) needs explicit review; it
is not silently treated as sixty minutes.
"""


def lockout_assessment(check_id, values):
    if not isinstance(values, dict):
        return None, "invalid_policy_value"
    threshold = values.get("lockout_threshold")
    if type(threshold) is not int or threshold < 0:
        return None, "missing_or_invalid_lockout_threshold"
    if threshold == 0:
        return False, "lockout_disabled"
    if check_id == "W-04":
        return threshold <= 5, "threshold_recommendation"
    if check_id != "W-08":
        raise ValueError("unsupported_lockout_check")
    times = [values.get(k) for k in ("lockout_duration", "reset_minutes")]
    if any(type(v) is not int or v < 0 for v in times):
        return None, "missing_or_invalid_duration"
    if times[0] == 0:
        return None, "manual_unlock_requires_policy_review"
    return all(v >= 60 for v in times), "duration_recommendation_with_enabled_lockout"
