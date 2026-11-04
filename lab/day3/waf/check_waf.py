"""Send a benign control and a disallowed method only to the internal WAF."""

from http.client import HTTPConnection, HTTPException
import json
import time
from uuid import uuid4


def request(method: str, path: str) -> tuple[int, bytes]:
    connection = HTTPConnection("waf", 8080, timeout=3)
    try:
        connection.request(method, path, headers={"User-Agent": "Day3Lab/1.0", "Accept": "text/plain"})
        response = connection.getresponse()
        return response.status, response.read(4096)
    finally:
        connection.close()


def main() -> int:
    run_id = uuid4().hex
    for attempt in range(10):
        try:
            control_status, body = request("GET", f"/day3-control?run={run_id}")
            if control_status not in {502, 503, 504}:
                break
        except (OSError, HTTPException):
            pass
        if attempt < 9:
            time.sleep(1)
    else:
        print("WAF or backend unavailable")
        return 1

    if (control_status, body) != (200, b"day3-backend-ok\n"):
        print(f"Backend control failed (HTTP {control_status})")
        return 1
    try:
        policy_status, _ = request("PUT", f"/day3-policy?run={run_id}")
    except (OSError, HTTPException):
        print("WAF policy request failed")
        return 1
    print(json.dumps({"run": run_id, "control_status": control_status, "policy_status": policy_status}))
    return int(policy_status != 403)


if __name__ == "__main__":
    raise SystemExit(main())
