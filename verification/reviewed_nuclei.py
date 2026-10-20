"""Opt-in, bounded Nuclei process runner; matches remain unconfirmed candidates.

The legacy NucleiRunner CVE verifier remains disabled: this module never asserts a CVE.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import subprocess
from urllib.parse import urlsplit


class NucleiExecutionError(RuntimeError):
    pass


def _resolved_template(root: Path, template: str, allowed_sha256: str) -> Path:
    base = root.resolve(strict=True)
    path = (base / template).resolve(strict=True)
    if path.suffix not in {".yaml", ".yml"} or base not in path.parents or not path.is_file():
        raise ValueError("Template must be a file inside approved template directory")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != allowed_sha256.lower():
        raise ValueError("Template hash differs from reviewed allowlist")
    return path


def _validate_target(url: str, allow_targets: set[str]) -> str:
    parts = urlsplit(url)
    if (parts.scheme not in {"http", "https"} or parts.username or parts.password
            or parts.query or parts.fragment or parts.path not in {"", "/"}):
        raise ValueError("Only explicit HTTP(S) origin URLs are supported")
    if parts.hostname is None or parts.port is None:
        raise ValueError("Explicit IP and port required")
    ip = str(ipaddress.ip_address(parts.hostname))
    if ip not in allow_targets:
        raise ValueError("Target not approved")
    canonical = f"{parts.scheme}://{'['+ip+']' if ':' in ip else ip}:{parts.port}"
    if url.rstrip("/") != canonical:
        raise ValueError("Use canonical exact IP:port origin")
    return canonical


def execute_reviewed(*, nuclei_binary: str, template_root: str, template_allowlist: dict,
                     template_name: str, origin: str, approved_ips: set[str],
                     timeout=30, max_results=100):
    """Use only a pinned reviewed template and numeric, explicitly approved target."""
    if not 1 <= timeout <= 120 or not 1 <= max_results <= 1000:
        raise ValueError("Resource bounds exceeded")
    if template_name not in template_allowlist:
        raise ValueError("Template not reviewed")
    target = _validate_target(origin, approved_ips)
    template = _resolved_template(Path(template_root), template_name, template_allowlist[template_name])
    binary = Path(nuclei_binary).resolve(strict=True)
    if not binary.is_file():
        raise ValueError("Nuclei executable missing")
    version = subprocess.run([str(binary), "-version"], capture_output=True, text=True, timeout=10,
                             check=False)
    if version.returncode != 0:
        raise NucleiExecutionError("Nuclei version invocation failed")
    # Avoid a process-wide shell and prevent passive upload/update mechanisms.
    args = [str(binary), "-u", target, "-t", str(template), "-jsonl",
            "-silent", "-disable-update-check", "-no-interactsh", "-rate-limit", "1",
            "-concurrency", "1", "-timeout", "5", "-retries", "0"]
    try:
        finished = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                  check=False, env={k: v for k,v in os.environ.items()
                                                   if k in {"PATH","HOME","TMPDIR","SYSTEMROOT","WINDIR"}})
    except subprocess.TimeoutExpired:
        return {"execution_status": "ERROR", "finding_status": "INCONCLUSIVE",
                "reason": "Nuclei execution timeout", "results": []}
    if finished.returncode != 0:
        return {"execution_status": "ERROR", "finding_status": "INCONCLUSIVE",
                "reason": "Nuclei returned nonzero exit", "results": []}
    rows = finished.stdout.splitlines()
    if len(rows) > max_results:
        raise NucleiExecutionError("Result count exceeds allowed maximum")
    observed = []
    for line in rows:
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise NucleiExecutionError("Malformed JSONL result") from exc
        if not isinstance(value, dict):
            raise NucleiExecutionError("Non-object JSONL result")
        # Store only reviewed non-secret keys, never request, response or cookies.
        observed.append({"template_id": str(value.get("template-id",""))[:160],
                         "severity": str(value.get("info",{}).get("severity",""))[:32],
                         "matched_at_sha256": hashlib.sha256(
                             str(value.get("matched-at","")).encode()).hexdigest()})
    return {"execution_status": "SUCCESS",
            "finding_status": "POTENTIAL" if observed else "NOT_DETECTED",
            "reason": "Template match needs separate CVE-specific verification",
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "template_sha256": template_allowlist[template_name],
            "version_output": (re.search(r"v[0-9]+\\.[0-9]+\\.[0-9]+", getattr(version, "stdout", "") + getattr(version, "stderr", "")) or ["UNAVAILABLE"])[0],
            "process_returncode": finished.returncode, "results": observed}
