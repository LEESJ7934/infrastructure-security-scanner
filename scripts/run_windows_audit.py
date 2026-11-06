"""Offline only. Never starts PowerShell, collects this host or connects remotely."""

import argparse
import json

from config_audit.collectors.windows_server import WindowsInputError, audit, load_bundle
from config_audit.windows_policy import WindowsPolicyError, load_policy, DEFAULT_POLICY


def main(argv=None):
    parser = argparse.ArgumentParser(description="Windows Server preparation / saved JSON audit only")
    parser.add_argument("--asset-id", default="WIN-LAB-SERVER")
    parser.add_argument("--input-json", help="Explicit normalized read-only export, never a raw policy backup")
    parser.add_argument("--expected-sha256", help="Independently retained source-file SHA-256")
    parser.add_argument("--synthetic", action="store_true", help="Simulation channel only, no device results")
    parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    parser.add_argument("--accept-policy-approval", action="store_true", help="Attest that actual approval authority and scope were reviewed")
    parser.add_argument("--before-json", help="Explicit baseline, never auto-selects the clock-invalid first export")
    parser.add_argument("--before-sha256", help="Independent baseline digest; never derived from the current file")
    parser.add_argument("--output-dir", help="Fresh directory for a separate Windows JSON/PDF report")
    parser.add_argument("--mode", choices=("STRICT", "LAB"), default="STRICT")
    parser.add_argument("--lab-criteria", help="Personal LAB criteria; no organization approval required")
    parser.add_argument("--lab-manual", help="Explicit user PowerShell confirmation record, kept separate from automatic JSON")
    args = parser.parse_args(argv)
    try:
        if (args.expected_sha256 or args.synthetic) and not args.input_json:
            raise WindowsInputError("input_required")
        bundle = load_bundle(args.input_json, expected_sha256=args.expected_sha256) if args.input_json else None
        policy_error = None
        try:
            policy = load_policy(args.policy, acknowledge_approval=args.accept_policy_approval)
        except WindowsPolicyError as error:
            if args.mode == "STRICT":
                raise
            # A broken organization approval record is an advanced-view error,
            # not a reason to block an independent personal LAB assessment.
            policy = None
            policy_error = {"status": "ERROR", "mode": "STRICT", "error_code": str(error)}
        if args.mode == "STRICT" and (args.lab_criteria or args.lab_manual):
            raise WindowsInputError("lab_arguments_require_lab_mode")
        if args.before_json or args.before_sha256 or args.output_dir:
            if not (args.before_json and args.input_json and args.output_dir) or args.synthetic:
                raise WindowsInputError("paired_report_arguments_required")
            from config_audit.windows_report import build_windows_report, write_windows_report
            report = policy_error or build_windows_report(args.before_json, args.input_json, before_sha256=args.before_sha256,
                after_sha256=args.expected_sha256, policy=policy)
            if bundle.document["asset_id"] != args.asset_id or any(row["asset_id_before"] != args.asset_id or row["asset_id_after"] != args.asset_id for row in report.get("changes", [])):
                raise WindowsInputError("asset_binding_mismatch")
            if args.mode == "LAB":
                from config_audit.windows_lab import build_lab_view, load_lab_manual, load_lab_criteria, DEFAULT_LAB_CRITERIA
                lab = build_lab_view(load_bundle(args.before_json, expected_sha256=args.before_sha256), bundle,
                    criteria=load_lab_criteria(args.lab_criteria or DEFAULT_LAB_CRITERIA),
                    manual=load_lab_manual(args.lab_manual) if args.lab_manual else None)
                lab["advanced_validation"] = report
                report = lab
            write_windows_report(report, args.output_dir)
            if args.mode == "LAB":
                print(json.dumps({"mode": "LAB", "summary": report["summary"],
                    "remediation_completed_count": report["remediation_completed_count"],
                    "advanced_comparison_summary": report["advanced_validation"].get("comparison", {}).get("summary"),
                    "advanced_error": policy_error}))
                return 0
            print(json.dumps({"mode": report["mode"], "comparison_summary": report["comparison"]["summary"],
                              "approval_status": policy.document["approval"]["status"]}))
            return 0
        if args.mode == "LAB":
            if bundle is None or args.synthetic:
                raise WindowsInputError("lab_mode_requires_explicit_saved_server_json")
            if bundle.document["asset_id"] != args.asset_id:
                raise WindowsInputError("asset_binding_mismatch")
            from config_audit.windows_lab import build_lab_view, load_lab_manual, load_lab_criteria, DEFAULT_LAB_CRITERIA
            report = build_lab_view(bundle, bundle, criteria=load_lab_criteria(args.lab_criteria or DEFAULT_LAB_CRITERIA),
                                    manual=load_lab_manual(args.lab_manual) if args.lab_manual else None)
            report["advanced_validation"] = policy_error or audit(bundle, asset_id=args.asset_id, policy=policy)
        else:
            report = audit(bundle, asset_id=args.asset_id, synthetic=args.synthetic, policy=policy)
    except (WindowsInputError, WindowsPolicyError) as error:
        print(json.dumps({"status": "ERROR", "error_code": str(error)}, ensure_ascii=True))
        return 2
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
