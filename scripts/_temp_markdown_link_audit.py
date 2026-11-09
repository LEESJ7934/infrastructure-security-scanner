"""Temporary full-tree Markdown link audit for one PR. Never accesses external URLs."""
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

ROOT=Path(__file__).resolve().parents[1]
files=[f.decode() for f in subprocess.check_output(["git","ls-files","-z"],cwd=ROOT).split(b"\0") if f]
md=[x for x in files if x.lower().endswith(".md")]
removed=[
"docs/phase2-final-integration.md",
"docs/validation.md",
"docs/progress/DAY3.md",
"docs/offline-reporting.md",
]
broken=[]
direct_refs=[]
count=0
for p in md:
    text=(ROOT/p).read_text("utf-8")
    for m in re.finditer(r"\]\(([^)\r\n]+)\)",text):
        raw=m.group(1).strip().strip("<>")
        if not raw or raw.startswith("#"):
            continue
        raw=raw.split(" '",1)[0].split(' "',1)[0]
        u=urlsplit(raw)
        if u.scheme or u.netloc or raw.startswith("//"):
            continue
        target=unquote(u.path)
        if not target:
            continue
        count+=1
        resolved=((ROOT/p).parent/target).resolve() if not target.startswith("/") else (ROOT/target[1:]).resolve()
        try: resolved.relative_to(ROOT)
        except ValueError:
            broken.append([p,raw,"outside_repository"])
            continue
        if not resolved.exists():
            broken.append([p,raw,"missing"])
        for old in removed:
            if target.endswith(old) or target==Path(old).name:
                direct_refs.append([p,raw])
for p in files:
    if p.endswith((".py",".md",".yml",".yaml",".json",".ps1",".sh",".tf",".conf",".txt")):
        try:
            content=(ROOT/p).read_text("utf-8")
        except UnicodeDecodeError:continue
        if p not in md and any(old in content for old in removed):
            direct_refs.append([p,"stale_deleted_document_name"])
print("MD_TOTAL",len(md),"MD_LINKS_CHECKED",count)
print("BROKEN_RELATIVE_LINKS",broken)
print("STALE_DOCUMENT_REFERENCES",direct_refs)
if broken or direct_refs:
    raise SystemExit(1)
