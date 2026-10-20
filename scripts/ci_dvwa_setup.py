"""Initialize an entirely disposable CI-only DVWA database; never run against EC2."""
import ipaddress
import os
import time
import requests
from bs4 import BeautifulSoup


def main():
    if os.environ.get("CI_DISPOSABLE_DVWA") != "YES" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("CI-only initialization guard denied")
    url = "http://127.0.0.1:4280"
    assert ipaddress.ip_address("127.0.0.1").is_loopback
    with requests.Session() as session:
        session.trust_env = False
        for attempt in range(25):
            try:
                page = session.get(url + "/setup.php", timeout=5, allow_redirects=False)
                if page.status_code == 200:
                    soup = BeautifulSoup(page.text, "html.parser")
                    token = soup.find("input", {"name": "user_token"})
                    if token and token.get("value"):
                        result = session.post(
                            url + "/setup.php",
                            data={"create_db": "Create / Reset Database",
                                  "user_token": token["value"]},
                            timeout=20, allow_redirects=False)
                        if result.status_code not in (200, 302, 303):
                            raise RuntimeError("DVWA setup HTTP failed")
                        # The database is verified independently in the CI workflow:
                        # A login form alone is NOT evidence that users were seeded.
                        print("Disposable DVWA setup request submitted; SQL seed verification required")
                        return
            except requests.RequestException:
                pass
            time.sleep(2)
    raise SystemExit("Disposable DVWA setup endpoint unavailable")


if __name__ == "__main__":
    main()
