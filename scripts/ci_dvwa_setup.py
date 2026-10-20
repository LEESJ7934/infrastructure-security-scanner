"""Initialize a disposable loopback-only DVWA CI database, never an existing EC2 lab."""
import ipaddress
import os
import time

import requests
from bs4 import BeautifulSoup


def main():
    if os.environ.get("CI_DISPOSABLE_DVWA") != "YES":
        raise SystemExit("Refusing to initialize a non-disposable DVWA database")
    url = "http://127.0.0.1:4280"
    assert ipaddress.ip_address("127.0.0.1").is_loopback
    with requests.Session() as session:
        session.trust_env = False
        for attempt in range(30):
            try:
                # The login form is the readiness check. Do not reset an already
                # initialized database, even within a disposable CI container.
                login = session.get(url + "/login.php", timeout=5, allow_redirects=False)
                if login.status_code == 200:
                    login_html = BeautifulSoup(login.text, "html.parser")
                    if login_html.find("input", {"name": "username"}):
                        print("Disposable DVWA login form ready; credentials withheld")
                        return
                setup = session.get(url + "/setup.php", timeout=5, allow_redirects=False)
                if setup.status_code == 200:
                    field = BeautifulSoup(setup.text, "html.parser").find("input", {"name": "user_token"})
                    if field and field.get("value"):
                        session.post(
                            url + "/setup.php",
                            data={"create_db": "Create / Reset Database",
                                  "user_token": field["value"]},
                            timeout=15, allow_redirects=False,
                        )
            except requests.RequestException:
                pass
            time.sleep(2)
        raise SystemExit("DVWA disposable database never reached usable login page")


if __name__ == "__main__":
    main()
