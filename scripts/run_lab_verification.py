"""Run separately recorded, scoped configuration checks for an existing scan."""
import argparse
import json
import sys
from pathlib import Path

from scanner.scope import ScopePolicy
from verification.lab_runner import execute


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    selection = p.add_mutually_exclusive_group(required=True)
    selection.add_argument("--scan-id", type=int)
    selection.add_argument("--asset-id")
    p.add_argument("--scope-file", type=Path, required=True)
    p.add_argument("--environment", required=True, choices=("LOCAL_BASELINE", "EC2_LAB"))
    p.add_argument("--allow-ftp-anonymous", action="store_true")
    p.add_argument("--ssh-policy-file", type=Path, help="Admin-attested JSON mapping exact IP:port to auth flags")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--timeout", type=float, default=5)
    args = p.parse_args(argv)
    try:
        if args.scan_id is not None and args.scan_id < 1:
            raise ValueError("Scan ID must be positive")
        policy = ScopePolicy.load(args.scope_file)
        ssh_policy = {}
        if args.ssh_policy_file:
            ssh_policy = json.loads(args.ssh_policy_file.read_text(encoding="utf-8"))
            if not isinstance(ssh_policy, dict):
                raise ValueError("SSH policy must be an object")
        result = execute(policy=policy, environment=args.environment,
                         asset_uid=args.asset_id, scan_id=args.scan_id,
                         allow_ftp_anonymous=args.allow_ftp_anonymous,
                         ssh_policy=ssh_policy, dry_run=args.dry_run, timeout=args.timeout)
        print(json.dumps({"results": result}, ensure_ascii=False, indent=2))
        return 1 if any(r.get("execution_status") == "ERROR" for r in result) else 0
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
