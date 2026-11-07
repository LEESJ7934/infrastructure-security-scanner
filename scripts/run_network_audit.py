"""Default preparation; explicit saved JSON or read-only local Docker collection."""
import argparse
import json
from pathlib import Path
from config_audit.collectors.network_devices import NetworkInputError, audit, load_bundle, collect_docker, apply_guard_export, attach_baseline


def main(argv=None):
    parser = argparse.ArgumentParser(description="Router/Switch personal LAB audit")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--execute", action="store_true", help="Read only fixed project-owned local Docker nodes; never start or change them")
    source.add_argument("--input-json")
    parser.add_argument("--synthetic", action="store_true", help="Synthetic fixtures only, no actual results")
    parser.add_argument("--output", help="New JSON path; parent must already exist; never overwrite")
    parser.add_argument("--guard-json", help="User-exported nft JSON for only inet/phase2_guard/input; reanalyzes R03, does not recollect other checks")
    parser.add_argument("--baseline-json", help="Link original saved before verdicts in a LAB comparison")
    args = parser.parse_args(argv)
    try:
        if args.synthetic and not args.input_json: raise NetworkInputError("synthetic_input_required")
        bundle = collect_docker() if args.execute else load_bundle(args.input_json)[0] if args.input_json else None
        supplemental = None
        if args.guard_json:
            if not args.input_json or args.synthetic: raise NetworkInputError("guard_export_requires_actual_saved_input")
            bundle, supplemental = apply_guard_export(bundle, args.guard_json)
        report = audit(bundle, synthetic=args.synthetic)
        if supplemental:
            report["mode"] = "LAB_OFFLINE_GUARD_RETEST"
            report["supplemental_guard_evidence"] = supplemental
            for row in report["results"]:
                if row["check_id"] != "NET-LAB-R03": row["verification_method"] = "saved_after_json_reused"
        if args.baseline_json:
            if args.synthetic or bundle is None: raise NetworkInputError("actual_baseline_requires_actual_result")
            attach_baseline(report, args.baseline_json)
        if args.output:
            try:
                with Path(args.output).open("x", encoding="utf-8") as stream: json.dump(report, stream, indent=2, ensure_ascii=True)
            except OSError: raise NetworkInputError("new_output_path_required") from None
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0
    except NetworkInputError as error:
        print(json.dumps({"status": "ERROR", "error_code": str(error), "results": audit(error_code=str(error))["results"]}))
        return 2


if __name__ == "__main__": raise SystemExit(main())
