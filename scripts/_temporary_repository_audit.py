"""Temporary inventory audit: inspect every Git-tracked file without executing the scanner."""
from __future__ import annotations

import ast
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
paths = [p.decode("utf-8") for p in subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0") if p]
contents = {}
textual = {}
for name in paths:
    data = (ROOT / name).read_bytes()
    contents[name] = data
    if b"\0" not in data:
        try:
            textual[name] = data.decode("utf-8")
        except UnicodeDecodeError:
            pass

# Explicit relative/full-path references and basename references are independent evidence.
basenames = Counter(Path(name).name for name in paths)
pmodules = {
    name[:-3].replace("/", ".").removesuffix(".__init__"): name
    for name in paths if name.endswith(".py")
}
refs = defaultdict(set)
module_refs = defaultdict(set)
literal_mentions = defaultdict(set)
for src, text in textual.items():
    if src.endswith(".py"):
        try:
            tree = ast.parse(text, filename=src)
        except SyntaxError:
            print(f"PARSE_ERROR {src}")
            continue
        src_parts = src.split("/")[:-1]
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [n.name for n in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    prefix = src_parts[:max(0, len(src_parts) - node.level + 1)]
                    fullname = ".".join(prefix + (node.module.split(".") if node.module else []))
                else:
                    fullname = node.module or ""
                mods = [fullname, *[fullname + "." + a.name for a in node.names]]
            for mod in mods:
                for m in [mod, *[".".join(mod.split(".")[:i]) for i in range(1, len(mod.split(".")))]]:
                    if m in pmodules and pmodules[m] != src:
                        module_refs[pmodules[m]].add(src)
    for path in paths:
        if src == path:
            continue
        # Literal repository-root-relative file/directory path occurrence.
        if "/" in path and path in text:
            literal_mentions[path].add(src)
        # Unique basename is a weak signal, not dependency proof.
        name = Path(path).name
        if len(name) >= 6 and basenames[name] == 1 and name in text:
            refs[path].add(src)

duplicates = defaultdict(list)
for path, data in contents.items():
    duplicates[hashlib.sha256(data).hexdigest()].append(path)
duplicates = [g for g in duplicates.values() if len(g) > 1]
prefixes = Counter(path.split("/")[0] if "/" in path else "(root)" for path in paths)
review = []
for path in paths:
    if not path.endswith(".py"):
        continue
    if path.endswith("/__init__.py"):
        continue
    if path.startswith("tests/") or path.startswith("scripts/"):
        continue
    if path.startswith("lab/") or path.startswith("infra/"):
        continue
    if path.startswith("config_audit/") or path.startswith("scanner/") or path.startswith("api/") or path.startswith("analysis/") or path.startswith("db/") or path.startswith("cloud_security/") or path.startswith("verification/") or path.startswith("asset_management/"):
        if not module_refs[path] and not literal_mentions[path] and not refs[path]:
            review.append(path)
review.sort()
suspects = [
    "config/scope.aws.legacy.json", "db/clear_tables.py", "tests/test.py",
    "scanner/probes.py", "scanner/version_parser.py", "analysis/fingerprint_parser.py",
    "api/generate_final_report.py"
]

print("=== REPOSITORY AUDIT BEGIN ===")
print("TRACKED_COUNT", len(paths), "TEXT_COUNT", len(textual), "BINARY_COUNT", len(paths)-len(textual))
print("PREFIX_COUNTS", json.dumps(prefixes, sort_keys=True))
print("DUPLICATE_CONTENT_GROUPS", json.dumps(duplicates, ensure_ascii=False))
print("ZERO_STATIC_REFERENCES_PY", json.dumps(review, ensure_ascii=False))
print("FOCUSED_CANDIDATES")
for name in suspects:
    if name in contents:
        print("CANDIDATE", name, "bytes",len(contents[name]),
              "module",len(module_refs[name]),"literal",len(literal_mentions[name]),
              "basename",len(refs[name]),
              "sources",json.dumps(sorted(module_refs[name] | literal_mentions[name] | refs[name])[:25],ensure_ascii=False))
print("FULL_FILE_INVENTORY_START")
for path in paths:
    category = ("documentation" if path.endswith(".md") else
                "test" if path.startswith("tests/") else
                "evidence" if path.startswith("evidence/") else
                "lab" if path.startswith("lab/") else
                "infrastructure" if path.startswith("infra/") else
                "workflow" if path.startswith(".github/") else
                "code" if path.endswith((".py",".ps1",".sh")) else "configuration_or_artifact")
    print("FILE",json.dumps({"path":path,"category":category,"size":len(contents[path]),
                              "module_refs":len(module_refs[path]),"literal_refs":len(literal_mentions[path]),
                              "basename_refs":len(refs[path]),"binary":path not in textual},ensure_ascii=False))
print("FULL_FILE_INVENTORY_END")
print("=== REPOSITORY AUDIT END ===")


print("DEPRECATED_IPS_REFERENCES")
for token in ("suricata_ips", "ips_execution", "run_suricata_ips", "phase2-ips", "phase2-suricata-ips"):
    hits = [path for path, text in textual.items()
            if token in text and path != "scripts/_temporary_repository_audit.py"]
    print("IPSTOKEN", token, json.dumps(hits, ensure_ascii=False))
print("CUSTOM_CONFIG_REFERENCES")
for token in ("app_config.yaml", "logging.conf", "scanner_config.yaml", "scope.aws.legacy.json"):
    hits = [path for path, text in textual.items()
            if token in text and path != "scripts/_temporary_repository_audit.py"]
    print("CONFIGTOKEN", token, json.dumps(hits, ensure_ascii=False))


# Final integrity gate: resolve Markdown targets and import modules within this repository.
from urllib.parse import unquote
all_paths = set(paths)
broken_links = []
for document, text in textual.items():
    if not document.endswith(".md"):
        continue
    for match in re.finditer(r"\]\(([^)\n]+)\)", text):
        dest = match.group(1).strip().split()[0].strip("<>")
        if not dest or dest.startswith(("#", "http:", "https:", "mailto:", "data:")):
            continue
        target = unquote(dest.split("#", 1)[0].split("?", 1)[0])
        if not target:
            continue
        full = (ROOT / document).parent.joinpath(target).resolve() if not target.startswith("/") else ROOT / target.lstrip("/")
        try:
            full.relative_to(ROOT)
        except ValueError:
            broken_links.append((document, dest, "outside-repo"))
            continue
        if not full.exists():
            broken_links.append((document, dest, "missing"))
internal_names = {"analysis", "api", "asset_management", "cloud_security", "config_audit", "db", "scanner", "scripts", "verification"}
missing_modules = []
for document, body in textual.items():
    if not document.endswith(".py"):
        continue
    try:
        tree = ast.parse(body)
    except SyntaxError:
        continue
    parent = document.split("/")[:-1]
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [n.name for n in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = parent[:max(0, len(parent)-node.level+1)]
                names = [".".join(parts+([node.module] if node.module else []))]
            else:
                names = [node.module or ""]
        for name in names:
            if not name or name.split(".")[0] not in internal_names:
                continue
            target = name.replace(".", "/")
            if target+".py" not in all_paths and target+"/__init__.py" not in all_paths and not any(x.startswith(target+"/") for x in all_paths):
                missing_modules.append((document, name))
print("BROKEN_MARKDOWN_LINKS", json.dumps(broken_links,ensure_ascii=False))
print("MISSING_INTERNAL_IMPORT_MODULES", json.dumps(missing_modules,ensure_ascii=False))
if broken_links or missing_modules:
    raise SystemExit("repository_integrity_check_failed")
