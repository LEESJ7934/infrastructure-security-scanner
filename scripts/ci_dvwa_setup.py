"""Initialize *disposable CI-only* DVWA DB; never invoke against EC2 or existing data.

The setup route can reset data and is therefore guarded by CI_DISPOSABLE_DVWA=YES.
"""
import os
import ipaddress

import requests
from bs4 import BeautifulSoup


def main():
    if os.environ.get("CI_DISPOSABLE_DVWA") != "YES":
        raise SystemExit("Refusing to initialize a non-disposable DVWA database")
    url = "http://127.0.0.1:4280"
    assert ipaddress.ip_address("127.0.0.1").is_loopback
    with requests.Session() as s:
        s.trust_env = False
        for _ in range(20):
            try:
                resp = s.get(url + "/setup.php", timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    break
            except requests.RequestException:
                pass
            __import__("time").sleep(2)
        else:
            raise SystemExit("DVWA not ready")
        html = BeautifulSoup(resp.text, "html.parser")
        field = html.find("input", {"name": "user_token"})
        if not field or not field.get("value"):
            raise SystemExit("Missing setup CSRF token")
        submission = s.post(url + "/setup.php",
                            data={"create_db": "Create / Reset Database", "user_token": field["value"]},
                            timeout=15, allow_redirects=False)
        if submission.status_code not in (200, 302, 303):
            raise SystemExit("DVWA disposable setup failed")
        print("Disposable isolated DVWA database initialized; no credentials logged")


if __name__ == "__main__":
    main()
