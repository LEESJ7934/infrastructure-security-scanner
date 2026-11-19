"""Non-secret raw observations, exclusive export and explicit offline import."""
from copy import deepcopy
import json
import os
from pathlib import Path
from .banner_grabber import sanitize_banner


def sanitized_scan(result):
    document = deepcopy(result)
    secret_keys = {"authorization", "proxy-authorization", "cookie", "set-cookie", "password", "token", "secret"}
    def clean(value):
        if isinstance(value, dict):
            return {key: ("[REDACTED]" if str(key).lower() in secret_keys else sanitize_banner(item) if key == "banner" and isinstance(item, (bytes, str)) else clean(item))
                    for key, item in value.items()}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value
    return clean(document)


def write_scan_artifact(result, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(sanitized_scan(result), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    with path.open("x", encoding="utf-8") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    return path


def load_scan_artifact(path):
    with Path(path).open("rb") as source:
        raw = source.read(64 * 1024 * 1024 + 1)
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError("Scan artifact exceeds size limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate artifact key")
            result[key] = value
        return result
    result = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique)
    if not isinstance(result, dict) or not isinstance(result.get("scan_id"), str) or not isinstance(result.get("targets"), list):
        raise ValueError("Invalid scan artifact")
    return sanitized_scan(result)
