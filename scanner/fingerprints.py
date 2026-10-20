"""Identify advertised products. A banner is evidence, never proof of a CVE."""
from __future__ import annotations

import re


PARSER_VERSION = "service-fingerprint-v1"
HTTP_PRODUCTS = {
    "apache": "apache_http_server",
    "nginx": "nginx",
    "microsoft-iis": "microsoft_iis",
}


def identify_service(banner: str | bytes | None, hint: str = "unknown") -> dict:
    result = {
        "parser_version": PARSER_VERSION,
        "service": hint or "unknown",
        "product": None,
        "version": None,
        "source": "port_hint",
        "confidence": "unknown",
        "evidence": None,
    }
    if not banner:
        return result
    raw = banner if isinstance(banner, bytes) else banner.encode("latin1", "replace")
    text = raw.decode("utf-8", "replace")

    def observed(service, product, version, source, evidence):
        result.update(service=service, product=product, version=version,
                      source=source, confidence="reported", evidence=evidence[:512])
        return result

    # MySQL protocol 10: packet header (4 bytes), protocol byte, NUL-terminated version.
    if len(raw) >= 6 and raw[3:5] == b"\x00\x0a" and b"\x00" in raw[5:]:
        greeting = raw[5:].split(b"\x00", 1)[0].decode("ascii", "replace")
        if re.fullmatch(r"[0-9][0-9A-Za-z.+_~:-]{0,200}", greeting):
            product = "mariadb" if "mariadb" in greeting.lower() else "mysql"
            version = greeting
            if product == "mariadb" and greeting.startswith("5.5.5-"):
                version = greeting[6:]
            return observed("mysql", product, version, "mysql_greeting", greeting)

    # A timeout/cap may cut a version token in half. Do not accept an unfinished line.
    if "\n" not in text:
        return result
    first_line = text.splitlines()[0] if text.splitlines() else ""
    if re.match(r"^SSH-(?:2\.0|1\.99)-", first_line):
        match = re.match(r"^SSH-(?:2\.0|1\.99)-OpenSSH_([^\s]+)", first_line, re.I)
        return observed("ssh", "openssh" if match else None,
                        match[1] if match else None, "ssh_greeting", first_line)

    if re.match(r"^220[ -]", first_line):
        match = re.search(r"\bvsftpd(?:\s+|/)([^\s)]+)", first_line, re.I)
        if match:
            return observed("ftp", "vsftpd", match[1], "ftp_greeting", first_line)
        # Explicit FTP wording distinguishes nonstandard lab ports from ambiguous SMTP 220.
        if re.search(r"\\bFTP\\b", first_line, re.I):
            return observed("ftp", None, None, "ftp_greeting", first_line)
        # Bare 220 is ambiguous between FTP and SMTP.
        return result

    if re.match(r"^HTTP/1\.[01] [0-9]{3}(?: |\r?$)", first_line):
        service = "https" if hint == "https" else "http"
        if not re.search(r"\r?\n\r?\n", text):
            return observed(service, None, None, "http_incomplete_headers", first_line)
        # Ignore the body, X-Powered-By and duplicate Server headers.
        header = re.split(r"\r?\n\r?\n", text, maxsplit=1)[0]
        servers = re.findall(r"^Server:[ \t]*([^\r\n]*)", header, re.I | re.M)
        if len(servers) != 1:
            return observed(service, None, None, "http_response", first_line)
        server = servers[0].strip()
        matches = list(re.finditer(
            r"(?:^|\s)(Apache|nginx|Microsoft-IIS)(?:/([^\s();]+))?(?=\s|$|[();])",
            server, re.I,
        ))
        if len(matches) != 1:
            return observed(service, None, None, "http_server", "Server: " + server)
        match = matches[0]
        return observed(service, HTTP_PRODUCTS[match[1].lower()], match[2],
                        "http_server", "Server: " + server)
    return result
