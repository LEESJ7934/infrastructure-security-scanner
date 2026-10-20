"""Extract a pinned official Nuclei archive only after checking its SHA-256.

Download the archive separately from the documented official release URL.
No installer, executable or target is run by this preparation command.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

VERSION = "v3.11.1"
ARCHIVES = {
    "linux_amd64": "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
    "windows_amd64": "bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2",
}


def prepare(archive, destination, platform):
    archive, destination = Path(archive), Path(destination)
    if platform not in ARCHIVES or archive.stat().st_size > 100_000_000:
        raise ValueError("Unsupported archive")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != ARCHIVES[platform]:
        raise ValueError("Official archive SHA-256 mismatch; do not execute")
    name = "nuclei.exe" if platform == "windows_amd64" else "nuclei"
    destination.mkdir(parents=True, exist_ok=True)
    binary = destination / name
    manifest = destination / "nuclei_identity.json"
    if binary.exists() or manifest.exists():
        raise ValueError("Use a new empty destination; existing binaries are never overwritten")
    with zipfile.ZipFile(archive) as package:
        item = package.getinfo(name)
        if item.file_size > 300_000_000:
            raise ValueError("Executable exceeds size bound")
        raw = package.read(item)
    with binary.open("xb") as output:
        output.write(raw)
    binary.chmod(0o755)
    identity = {"version": VERSION, "binary_sha256": hashlib.sha256(raw).hexdigest(),
                "archive_sha256": digest, "platform": platform,
                "source": f"https://github.com/projectdiscovery/nuclei/releases/tag/{VERSION}"}
    with manifest.open("x", encoding="utf-8") as output:
        json.dump(identity, output, indent=2)
    return identity


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True)
    p.add_argument("--destination", default="evidence/tools/nuclei")
    p.add_argument("--platform", choices=tuple(ARCHIVES), required=True)
    a = p.parse_args(argv)
    try:
        print(json.dumps(prepare(a.archive, a.destination, a.platform)))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "NOT_PREPARED", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
