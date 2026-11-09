"""Read-only, explicitly scoped evidence integrity checks, never audit verdicts.

No scanning, collectors, shell commands or network. Expected hashes must come
from caller-supplied declarations, never from this run's computed digest.
Windows opens refuse reparse targets and validate the final handle path before
reading. POSIX opens use descriptor-relative, no-follow traversal.
"""

from collections import Counter
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import stat

from .reporting import OfflineReport, SENSITIVE

STATES = ("VERIFIED", "MISMATCH", "MISSING", "NOT_VERIFIED", "EXTERNAL_REFERENCE", "INVALID_REFERENCE")
ALLOWED_FILES = ("logs/day2-before.json", "logs/day2-after.json", "logs/day3-final.json")
ALLOWED_TREES = ("lab/ids-waf-lab/artifacts", "evidence/day4")
CHANNELS = {"automatic", "manual", "pf", "log_analysis", "snapshot_input", "local_artifact"}
MAX_BINDINGS = 16384
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
REPARSE_POINT = 0x400
LIMITATIONS = ("hash_match_does_not_prove_authenticity_or_collection_completeness",
               "expected_hash_provenance_is_a_caller_or_stored_document_declaration",
               "only_explicit_references_checked_no_directory_discovery",
               "verification_is_not_a_new_traffic_test_or_audit_verdict")


class EvidenceAccessError(ValueError):
    """Fixed codes only; never expose OS exceptions or file contents."""


def require(condition, code):
    if not condition:
        raise EvidenceAccessError(code)


@dataclass(frozen=True)
class EvidenceBinding:
    reference: str
    asset_id: str | None = None
    check_id: str | None = None
    day: int | None = None
    snapshot_id: str | None = None
    channel: str = "local_artifact"
    relative_to: str | None = None
    expected_sha256: str | None = None
    expected_hash_source: str | None = None
    rule_version: str | None = None
    role: str = "evidence_reference"


def _sensitive_path(path):
    for part in path.parts:
        name = part.casefold()
        if (name in {".git", ".ssh", ".aws", ".gnupg", ".venv", "secrets", "credentials"}
                or name == ".env" or name.startswith(".env.")
                or name.startswith(("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"))
                or Path(name).suffix in {".key", ".pem", ".pfx", ".p12", ".keystore", ".jks"}
                or re.search(r"api[-_ ]?(?:key|secret)|private[-_ ]?key|credential|"
                             r"(?:^|[._ -])(?:secrets?|tokens?|passwords?)(?:$|[._ -])", name)):
            return True
    return False


def _plain(value):
    require(isinstance(value, str) and 0 < len(value) <= 4096
            and not any(ord(char) < 32 or ord(char) == 127 for char in value), "reference_invalid")
    return value


def _path_syntax(value):
    _plain(value)
    require(not value.startswith(("\\\\", "//")), "unc_or_device_path_denied")
    parts = value.replace("\\", "/").split("/")
    require(".." not in parts, "parent_traversal_denied")
    for part in parts:
        if part in {"", "."} or re.fullmatch(r"[A-Za-z]:", part):
            continue
        require(not part.endswith((".", " ")), "ambiguous_windows_path_denied")
        require(not re.fullmatch(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part, re.I),
                "device_name_denied")
    return value


class EvidencePolicy:
    """Fixed project-internal allowlist. A caller cannot broaden it with input."""

    def __init__(self, project_root):
        self.root = Path(project_root).resolve(strict=True)
        require(self.root.is_dir(), "project_root_invalid")
        self.root_stat = self.root.stat()

    def allowed(self, path):
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            return False
        return (relative in {Path(item) for item in ALLOWED_FILES}
                or any(relative.is_relative_to(Path(tree)) for tree in ALLOWED_TREES))

    def path(self, reference, base=None):
        _path_syntax(reference)
        native = reference.replace("\\", os.sep)
        drive, tail = ntpath.splitdrive(reference)
        if drive:
            require(os.name == "nt" and len(drive) == 2 and drive[1] == ":"
                    and tail.startswith(("/", "\\")), "foreign_or_relative_drive_denied")
            require(":" not in tail, "alternate_stream_denied")
        else:
            require(":" not in reference, "alternate_stream_denied")
            if os.name == "nt":
                require(not reference.startswith(("/", "\\")), "root_relative_path_denied")
        candidate = Path(native)
        if not candidate.is_absolute():
            if base is None:
                parent = self.root
            else:
                _path_syntax(base)
                parent = Path(base.replace("\\", os.sep))
                # Bases are metadata only, but cannot redirect access outside root.
                if not parent.is_absolute():
                    require(not ntpath.splitdrive(base)[0] and ":" not in base,
                            "base_path_invalid")
                    parent = self.root / parent
                else:
                    base_drive, base_tail = ntpath.splitdrive(base)
                    require(":" not in base_tail, "alternate_stream_denied")
                    require(not base_drive or os.name == "nt" and len(base_drive) == 2,
                            "base_path_invalid")
                require(parent.is_relative_to(self.root), "base_outside_project")
            candidate = parent / candidate
        require(candidate.is_relative_to(self.root), "outside_project")
        require(not _sensitive_path(candidate.relative_to(self.root)), "sensitive_file_denied")
        require(self.allowed(candidate), "outside_evidence_allowlist")
        return candidate

    def inspect(self, candidate):
        """lstat each component before opening; no symlink/junction is trusted."""
        current = self.root
        info = None
        for part in candidate.relative_to(self.root).parts:
            current = current / part
            info = os.lstat(current)
            require(not stat.S_ISLNK(info.st_mode)
                    and not getattr(info, "st_file_attributes", 0) & REPARSE_POINT,
                    "symlink_or_reparse_point_denied")
        require(info is not None and stat.S_ISREG(info.st_mode), "not_a_regular_file")
        require(info.st_nlink == 1, "hard_link_denied")
        return info


def _windows_open(candidate):
    # OPEN_REPARSE_POINT protects the final component. The final handle path
    # also detects a parent junction substituted between lstat and CreateFile.
    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    final = kernel.GetFinalPathNameByHandleW
    final.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    final.restype = wintypes.DWORD
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    handle = create(str(candidate), 0x80000000, 1, None, 3, 0x00200000 | 0x08000000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise EvidenceAccessError("file_open_failed")
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        length = final(handle, buffer, len(buffer), 0)
        require(0 < length < len(buffer), "final_path_unavailable")
        actual = buffer.value
        require(actual.startswith("\\\\?\\") and not actual.startswith("\\\\?\\UNC\\"), "final_path_denied")
        actual = actual[4:]
        require(ntpath.normcase(actual) == ntpath.normcase(str(candidate)), "file_path_changed")
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None  # Descriptor now owns the Windows handle.
        return descriptor
    finally:
        if handle is not None:
            close(handle)


def _open_file(policy, candidate):
    if os.name == "nt":
        return _windows_open(candidate)
    # POSIX: pin every parent directory and refuse links on every open.
    directory = os.open(policy.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        require((info.st_dev, info.st_ino) == (policy.root_stat.st_dev, policy.root_stat.st_ino),
                "project_root_changed")
        parts = candidate.relative_to(policy.root).parts
        for part in parts[:-1]:
            next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)


def _fingerprint(info):
    # On Windows stat(path) and fstat(handle) can report different historical
    # meanings for ctime (creation vs change time). File ID/size/mtime are shared;
    # the Windows read handle additionally disallows write/delete sharing.
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns if os.name != "nt" else None)


def _hash_file(policy, candidate, before, budget):
    require(before.st_size <= MAX_FILE_BYTES, "file_size_limit")
    require(before.st_size <= budget, "total_read_limit")
    descriptor = _open_file(policy, candidate)
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                and not getattr(opened, "st_file_attributes", 0) & REPARSE_POINT,
                "unsafe_opened_file")
        require(_fingerprint(opened) == _fingerprint(before), "file_changed_during_verification")
        digest, count = hashlib.sha256(), 0
        while True:
            block = os.read(descriptor, min(65536, MAX_FILE_BYTES - count + 1, budget - count + 1))
            if not block:
                break
            count += len(block)
            require(count <= MAX_FILE_BYTES and count <= budget, "read_size_limit")
            digest.update(block)
        after = os.fstat(descriptor)
        require(count == before.st_size and _fingerprint(after) == _fingerprint(before),
                "file_changed_during_verification")
        require(_fingerprint(policy.inspect(candidate)) == _fingerprint(after), "file_path_changed")
        return digest.hexdigest(), count
    finally:
        os.close(descriptor)


def _external(reference, day):
    # These references remain opaque; no basename or /tmp-to-local substitution.
    if re.match(r"^(?:https?://|manual:|day4:)", reference, re.I):
        return True
    if re.match(r"^[A-Za-z0-9_.-]{2,}:/", reference):
        return True
    if ("#" in reference and not ntpath.splitdrive(reference)[0]
            and not reference.startswith(("/", "\\", ".", "logs/", "lab/", "evidence/"))):
        return True
    return day == 3 and reference.startswith("/tmp/")


def _identity(binding):
    return {key: getattr(binding, key) for key in (
        "asset_id", "check_id", "day", "snapshot_id", "channel", "reference", "relative_to",
        "expected_sha256", "expected_hash_source", "rule_version", "role")}


def _verify(policy, binding, verified_at, budget):
    identity = _identity(binding)
    entry = {**identity, "original_reference": identity.pop("reference"),
             "local_path": None, "exists": None, "actual_sha256": None,
             "size_bytes": None, "status": "INVALID_REFERENCE", "hash_comparison": "NOT_COMPARED",
             "verified_at": verified_at, "error": None, "limitations": list(LIMITATIONS)}
    entry.pop("reference", None)
    consumed = 0
    try:
        _plain(binding.reference)
        # Never serialize authentication strings even as an invalid reference.
        require(not SENSITIVE.search(binding.reference), "sensitive_reference_denied")
        require(binding.expected_sha256 is None or isinstance(binding.expected_sha256, str)
                and re.fullmatch(r"[a-fA-F0-9]{64}", binding.expected_sha256), "expected_sha256_invalid")
        _path_syntax(binding.reference)
        if _external(binding.reference, binding.day):
            entry["status"] = "EXTERNAL_REFERENCE"
            return entry, consumed
        candidate = policy.path(binding.reference, binding.relative_to)
        entry["local_path"] = str(candidate)
        try:
            info = policy.inspect(candidate)
        except FileNotFoundError:
            entry.update(status="MISSING", exists=False, error="file_missing")
            return entry, consumed
        entry.update(exists=True, size_bytes=info.st_size, status="NOT_VERIFIED")
        # Reserve attempted reads even on errors, preventing repeated failed
        # bindings from bypassing the total I/O budget.
        consumed = min(info.st_size + 1, MAX_FILE_BYTES + 1, budget)
        digest, _ = _hash_file(policy, candidate, info, budget)
        entry["actual_sha256"] = digest
        if binding.expected_sha256 is not None:
            match = digest == binding.expected_sha256.lower()
            entry.update(status="VERIFIED" if match else "MISMATCH",
                         hash_comparison="MATCH" if match else "MISMATCH")
        else:
            entry["limitations"].append("independent_expected_sha256_not_supplied")
    except EvidenceAccessError as exc:
        entry["error"] = str(exc)
        if entry["status"] == "INVALID_REFERENCE":
            entry["local_path"] = None
        if str(exc) == "sensitive_reference_denied":
            entry["original_reference"] = "[REDACTED]"
        if str(exc) == "expected_sha256_invalid":
            entry["expected_sha256"] = None
    except (OSError, ValueError):
        entry["error"] = "file_access_failed"
        if entry["status"] == "INVALID_REFERENCE":
            entry["local_path"] = None
    return entry, consumed


def report_bindings(report, *, include_snapshot_sources=True):
    """Keep every asset/check/channel association, without inferring mappings."""
    require(isinstance(report, OfflineReport), "report_invalid")
    bindings = []
    for snapshot in report.snapshots:
        if include_snapshot_sources and not snapshot.results:
            bindings.append(EvidenceBinding(snapshot.source, day=snapshot.day, snapshot_id=snapshot.snapshot_id,
                                            channel="snapshot_input", role="source_snapshot"))
        for row in snapshot.results:
            context = dict(asset_id=row.asset_id, check_id=row.check_id, day=snapshot.day,
                           snapshot_id=snapshot.snapshot_id, rule_version=row.rule_version)
            if include_snapshot_sources:
                bindings.append(EvidenceBinding(snapshot.source, **context, channel="snapshot_input", role="source_snapshot"))
            channels = {"automatic": row.automatic, "manual": row.manual,
                        "pf": row.analyses.get("pf_snapshot"), "log_analysis": row.analyses.get("log_rule_evidence")}
            for name, channel in channels.items():
                if channel is None:
                    continue
                for reference in channel.get("evidence_references", []):
                    bindings.append(EvidenceBinding(
                        reference["reference"], **context, channel=name,
                        relative_to=reference.get("relative_to"),
                        expected_sha256=reference.get("declared_sha256"),
                        expected_hash_source="stored_reference_declaration" if reference.get("declared_sha256") else None))
    for reference in report.evidence_sources:
        bindings.append(EvidenceBinding(reference["reference"], relative_to=reference.get("relative_to"),
                                        expected_sha256=reference.get("declared_sha256"),
                                        expected_hash_source="stored_reference_declaration" if reference.get("declared_sha256") else None))
    return bindings


def build_evidence_index(report, *, project_root, extra_bindings=(), include_snapshot_sources=True):
    """Return a deterministic index. Hashes are checked at verified_at, not generated_at.

    Duplicate bindings collapse; different associations or expectations remain
    separate entries. No file discovery occurs. Raw files may be linked through
    explicit extra_bindings, with unassigned context when provenance is unknown.
    """
    policy = EvidencePolicy(project_root)
    bindings = [*report_bindings(report, include_snapshot_sources=include_snapshot_sources), *extra_bindings]
    require(len(bindings) <= MAX_BINDINGS, "binding_limit")
    verified_at = datetime.now(timezone.utc).isoformat()
    unique = {}
    for binding in bindings:
        require(isinstance(binding, EvidenceBinding), "binding_invalid")
        require(isinstance(binding.channel, str) and binding.channel in CHANNELS
                and (binding.day is None or type(binding.day) is int and binding.day in (2, 3, 4)),
                "binding_context_invalid")
        for value in (binding.asset_id, binding.check_id, binding.snapshot_id, binding.rule_version,
                      binding.expected_hash_source, binding.relative_to, binding.role):
            require(value is None or isinstance(value, str) and len(value) <= 4096 and not SENSITIVE.search(value),
                    "binding_metadata_invalid")
        require(isinstance(binding.reference, str) and len(binding.reference) <= 4096, "reference_invalid")
        require(binding.expected_sha256 is None or isinstance(binding.expected_sha256, str), "expected_sha256_invalid")
        # Stable IDs include relationships and declarations, not timestamps or
        # current content hashes, so file tampering does not change a binding ID.
        key = json.dumps(_identity(binding), sort_keys=True, ensure_ascii=True)
        unique[key] = binding
    entries, budget = [], MAX_TOTAL_BYTES
    for key in sorted(unique):
        entry, consumed = _verify(policy, unique[key], verified_at, budget)
        budget -= consumed
        entry["evidence_id"] = "ev-" + hashlib.sha256(key.encode("utf-8")).hexdigest()
        entries.append(entry)
    counts = Counter(entry["status"] for entry in entries)
    return {"schema_version": 1, "verified_at": verified_at, "entries": entries,
            "counts": {state: counts[state] for state in STATES},
            "unique_local_files": len({e["local_path"] for e in entries if e["exists"] is True}),
            "duplicate_bindings_removed": len(bindings) - len(unique), "limitations": list(LIMITATIONS)}


def attach_evidence_index(report, index):
    """Return a new model with channel-specific IDs, preserving all verdicts."""
    require(isinstance(report, OfflineReport) and isinstance(index, dict) and index.get("schema_version") == 1,
            "index_invalid")
    snapshots = []
    for snapshot in report.snapshots:
        rows = []
        for row in snapshot.results:
            links = {}
            for entry in index["entries"]:
                if (entry["snapshot_id"], entry["asset_id"], entry["check_id"], entry["rule_version"]) == (
                        snapshot.snapshot_id, row.asset_id, row.check_id, row.rule_version):
                    links.setdefault(entry["channel"], []).append(entry["evidence_id"])
            rows.append(replace(row, evidence_index_ids={name: tuple(sorted(ids)) for name, ids in sorted(links.items())}))
        snapshots.append(replace(snapshot, results=tuple(rows)))
    return replace(report, snapshots=tuple(snapshots), evidence_index=deepcopy(index))
