"""Upload harmless fixtures to the disposable baseline and improved local DVWA."""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
import struct
import subprocess
from urllib.parse import quote
from uuid import uuid4
import zlib

from bs4 import BeautifulSoup
from PIL import Image
import requests

from test_http_comparison import TIMEOUT, login


ENDPOINT = "/vulnerabilities/upload/"
PUBLIC_URL = "/hackable/uploads/"
PUBLIC_DIR = "/var/www/html/hackable/uploads"
PRIVATE_DIR = "/var/lib/dvwa-uploads"
TARGETS = {
    "baseline": ("http://127.0.0.1:4282", "scanner-dvwa-upload-baseline-web-1"),
    "after": ("http://127.0.0.1:4281", "scanner-dvwa-sqli-retest-web-1"),
}
EXPECTED = {
    "baseline": {"png": 200, "jpeg": 200, "txt": 200, "txt_as_png": 200},
    "after": {"png": 201, "jpeg": 201, "txt": 415, "txt_as_png": 415, "png_as_jpeg": 415,
              "truncated_png": 415, "exact_limit": 201, "over_limit": 413, "over_php_limit": 413,
              "oversize_dimensions": 413, "empty": 400, "no_file": 400, "same_filename": 201},
}
MESSAGES = {
    "txt": "Use a PNG or JPEG image with a matching extension.",
    "txt_as_png": "Use a PNG or JPEG image with a matching extension.",
    "png_as_jpeg": "Use a PNG or JPEG image with a matching extension.",
    "truncated_png": "The image could not be decoded.",
    "over_limit": "Image exceeds the upload size limit.",
    "over_php_limit": "Image exceeds the upload size limit.",
    "oversize_dimensions": "Image dimensions exceed 2048 by 2048 pixels.",
    "empty": "The upload is empty or unreadable.",
    "no_file": "Provide a single complete image upload.",
}
SNAPSHOT_PHP = """
$root = $argv[1];
if (!is_dir($root)) { exit(2); }
$entries = [];
$fileInfo = new finfo(FILEINFO_MIME_TYPE);
foreach (new FilesystemIterator($root) as $item) {
    $file = $item->getPathname();
    $record = ['type' => $item->getType()];
    if ($record['type'] === 'file') {
        $record += ['bytes' => $item->getSize(), 'sha256' => hash_file('sha256', $file),
                    'mode' => decoct($item->getPerms() & 0777), 'mime' => $fileInfo->file($file)];
    }
    $entries[$item->getFilename()] = $record;
}
echo json_encode((object) $entries, JSON_THROW_ON_ERROR);
"""


def image_bytes(image_format, size=(8, 8)):
    with Image.new("RGB", size, (32, 128, 192)) as image, BytesIO() as output:
        image.save(output, format=image_format)
        return output.getvalue()


def padded_png(png, length):
    # Insert a legal, inert PNG tEXt chunk before IEND to reach an exact input size.
    payload = b"Comment\0" + b"A" * (length - len(png) - 20)
    chunk = b"tEXt" + payload
    return png[:-12] + struct.pack(">I", len(payload)) + chunk + struct.pack(">I", zlib.crc32(chunk)) + png[-12:]


def make_fixtures(run_prefix):
    png = image_bytes("PNG")
    harmless_text = b"DVWA file upload test. Harmless plain text.\n"
    return {
        "png": (f"{run_prefix}-image.PNG", png, "image/png"),
        "jpeg": (f"{run_prefix}-image.jpeg", image_bytes("JPEG"), "application/octet-stream"),
        "txt": (f"{run_prefix}-text.txt", harmless_text, "text/plain"),
        "txt_as_png": (f"{run_prefix}-disguised.png", harmless_text, "image/png"),
        "png_as_jpeg": (f"{run_prefix}-mismatch.jpg", png, "image/jpeg"),
        "truncated_png": (f"{run_prefix}-truncated.png", png[:45], "image/png"),
        "exact_limit": (f"{run_prefix}-limit.png", padded_png(png, 100000), "image/png"),
        "over_limit": (f"{run_prefix}-over.png", padded_png(png, 100001), "image/png"),
        "over_php_limit": (f"{run_prefix}-over-php.png", padded_png(png, 2 * 1024 * 1024 + 1), "image/png"),
        "oversize_dimensions": (f"{run_prefix}-wide.png", image_bytes("PNG", (2049, 1)), "image/png"),
        "empty": (f"{run_prefix}-empty.png", b"", "image/png"),
        "no_file": ("", b"", "application/octet-stream"),
        "same_filename": (f"{run_prefix}-image.PNG", png, "image/png"),
    }


def docker_snapshot(container, directories):
    result = {}
    for label, path in directories.items():
        command = ["docker", "exec", container, "php", "-r", SNAPSHOT_PHP, "--", path]
        completed = subprocess.run(command, check=True, capture_output=True, timeout=30)
        result[label] = json.loads(completed.stdout)
    return result


def prepare(fixture):
    request = requests.Request("POST", "http://127.0.0.1" + ENDPOINT, data={"Upload": "Upload"},
                               files={"uploaded": fixture}).prepare()
    return request.body, request.headers["Content-Type"]


def fs_changes(before, after):
    return {
        path: {"added": {name: current[name] for name in current.keys() - before[path].keys()},
               "removed": len(before[path].keys() - current.keys()),
               "modified": sum(current[name] != before[path][name] for name in current.keys() & before[path].keys())}
        for path, current in after.items()
    }


def run_case(session, stage, case, status, fixture, multipart):
    origin, container = TARGETS[stage]
    dirs = {"web_uploads": PUBLIC_DIR}
    if stage == "after":
        dirs["private_uploads"] = PRIVATE_DIR
    before = docker_snapshot(container, dirs)
    name, content, part_mime = fixture
    body, content_type = multipart
    response = session.post(origin + ENDPOINT, data=body, headers={"Content-Type": content_type},
                            timeout=TIMEOUT, allow_redirects=False)
    after = docker_snapshot(container, dirs)
    changes = fs_changes(before, after)
    before_names_unchanged = all(item["removed"] == item["modified"] == 0 for item in changes.values())

    soup = BeautifulSoup(response.content, "html.parser")
    messages = [pre.decode_contents() for pre in soup.select(".vulnerable_code_area pre")]
    low = bool(re.search(r"\bSecurity Level:\s*low\b", soup.get_text(" ", strip=True), re.IGNORECASE))
    cookie = response.request.headers.get("Cookie", "")
    low_sent = re.findall(r"(?:^|;\s*)security=([^;]*)", cookie) == ["low"]
    valid = (response.status_code == status and low and low_sent and before_names_unchanged
             and response.request.path_url == ENDPOINT and response.request.method == "POST"
             and response.request.body == body and response.request.headers["Content-Type"] == content_type)
    reads = {}
    excerpt = None
    if stage == "baseline":
        expected = f"../../hackable/uploads/{name} succesfully uploaded!"
        excerpt = expected if messages == [expected] else None
        public = session.get(origin + PUBLIC_URL + quote(name), timeout=TIMEOUT, allow_redirects=False)
        reads["original_public_path"] = {"status": public.status_code, "sha256": sha256(public.content).hexdigest()}
        added = changes["web_uploads"]["added"]
        valid = (valid and excerpt is not None and set(added) == {name} and public.status_code == 200
                 and public.content == content and added[name]["sha256"] == sha256(content).hexdigest())
    elif status == 201:
        match = re.fullmatch(r"Image uploaded\. ID: ([a-f0-9]{32}\.(?:png|jpg))", messages[0]) if len(messages) == 1 else None
        identifier = match[1] if match else ""
        excerpt = match[0] if match else None
        added = changes["private_uploads"]["added"]
        expected_extension = ".jpg" if case == "jpeg" else ".png"
        expected_mime = "image/jpeg" if case == "jpeg" else "image/png"
        valid = (valid and identifier.endswith(expected_extension) and set(added) == {identifier}
                 and not changes["web_uploads"]["added"] and added[identifier]["mode"] == "600"
                 and added[identifier]["mime"] == expected_mime and added[identifier]["bytes"] > 0
                 and (case != "exact_limit" or added[identifier]["bytes"] < len(content)))
        if identifier:
            for label, prefix in {"public_upload_path": PUBLIC_URL, "private_dir_name_as_url": "/dvwa-uploads/"}.items():
                result = session.get(origin + prefix + identifier, timeout=TIMEOUT, allow_redirects=False)
                reads[label] = {"status": result.status_code}
                valid = valid and result.status_code == 404
    else:
        excerpt = MESSAGES[case] if messages == [MESSAGES[case]] else None
        valid = valid and excerpt is not None and before == after

    return {
        "request": {"method": response.request.method, "target": ENDPOINT, "security_level": "low" if low_sent else None,
                    "filename": name, "part_content_type": part_mime, "file_bytes": len(content),
                    "file_sha256": sha256(content).hexdigest(), "multipart_sha256": sha256(body).hexdigest()},
        "response": {"status": response.status_code, "content_type": response.headers.get("Content-Type"),
                     "body_bytes": len(response.content), "body_sha256": sha256(response.content).hexdigest(),
                     "message_excerpt": excerpt, "low_page": low},
        "storage_diff": changes, "http_read_checks": reads, "verdict": "PASS" if valid else "FAIL",
    }


def compare(evidence):
    fixtures = make_fixtures("dvwa-upload-" + uuid4().hex[:12])
    requests_by_case = {case: prepare(fixture) for case, fixture in fixtures.items()}
    for stage, (origin, container) in TARGETS.items():
        target = {"origin": origin, "container": container, "cases": {}}
        evidence["targets"][stage] = target
        with requests.Session() as session:
            session.trust_env = False
            try:
                login(session, origin, "admin", "password")
                for case, status in EXPECTED[stage].items():
                    record = run_case(session, stage, case, status, fixtures[case], requests_by_case[case])
                    target["cases"][case] = record
                    if record["verdict"] != "PASS":
                        evidence["errors"].append(f"{stage}/{case}: response or storage assertion failed")
            except (RuntimeError, requests.RequestException, subprocess.SubprocessError, OSError, ValueError) as error:
                evidence["errors"].append(f"{stage}: {type(error).__name__}")

    for case in EXPECTED["baseline"]:
        original = evidence["targets"]["baseline"]["cases"].get(case)
        improved = evidence["targets"]["after"]["cases"].get(case)
        evidence["matched_requests"][case] = bool(original and improved and original["request"] == improved["request"])
    if not all(evidence["matched_requests"].values()):
        evidence["errors"].append("Could not confirm identical requests for shared cases")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new path for sanitized HTTP and storage evidence")
    args = parser.parse_args()
    evidence = {"finding_id": "DVWA-UPLOAD-LOW", "cwe": "CWE-434",
                "captured_at_utc": datetime.now(timezone.utc).isoformat(), "targets": {}, "matched_requests": {}, "errors": []}
    with args.output.open("x", encoding="utf-8") as output:
        compare(evidence)
        evidence["verdict"] = "FAIL" if evidence["errors"] else "PASS"
        output.write(json.dumps(evidence, indent=2) + "\n")
    for stage, target in evidence["targets"].items():
        for case, record in target["cases"].items():
            added = sum(len(path["added"]) for path in record["storage_diff"].values())
            print(f"{stage}/{case}: HTTP {record['response']['status']}, {added} new files ({record['verdict']})")
    for error in evidence["errors"]:
        print(error)
    return 0 if evidence["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
