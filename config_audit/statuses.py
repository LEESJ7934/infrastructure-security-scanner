from enum import StrEnum


class AuditStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_TESTED = "NOT_TESTED"
    ERROR = "ERROR"
