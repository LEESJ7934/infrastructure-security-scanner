"""Offline/preparation by default; explicit fixed-scope Docker read-only mode."""
import argparse
import json
from pathlib import Path
from config_audit.collectors.web_was import WebInputError, audit, collect_docker, compare, load_bundle, synthetic_bundle


def main(argv=None):
    parser = argparse.ArgumentParser(description="Nginx/Tomcat personal LAB audit; never changes containers")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--execute", action="store_true")
    source.add_argument("--input-json")
    source.add_argument("--demo", choices=("before", "after"), help="Clearly labelled synthetic template tests only")
    parser.add_argument("--synthetic", action="store_true", help="Required to import saved synthetic JSON")
    parser.add_argument("--baseline-json")
    parser.add_argument("--output")
    parser.add_argument("--pdf")
    args = parser.parse_args(argv)
    try:
        if args.synthetic and not args.input_json: raise WebInputError("synthetic_input_required")
        for path in (args.output, args.pdf):
            if path and (Path(path).exists() or Path(path).is_symlink()): raise WebInputError("new_output_path_required")
        if args.pdf and args.output and Path(args.pdf).resolve() == Path(args.output).resolve(): raise WebInputError("distinct_outputs_required")
        bundle = collect_docker() if args.execute else load_bundle(args.input_json)[0] if args.input_json else synthetic_bundle(args.demo) if args.demo else None
        report = audit(bundle, synthetic=bool(args.demo or args.synthetic))
        if args.baseline_json: compare(report, args.baseline_json)
        if args.pdf:
            from config_audit.web_was_report import write_pdf
            # Reserve exclusively to protect an existing file even during races.
            with Path(args.pdf).open("xb") as stream: write_pdf(report, stream)
        if args.output:
            with Path(args.output).open("x", encoding="utf-8") as stream: json.dump(report, stream, ensure_ascii=False, indent=2)
        print(json.dumps({"mode": report["mode"], "origin": report["origin"], "summary": report["summary"],
            "http_verification": report["http_verification"], "comparison_summary": report.get("comparison", {}).get("summary")}, ensure_ascii=False))
        return 0
    except WebInputError as error:
        print(json.dumps({"status": "ERROR", "error_code": str(error)}))
        return 2
    except (OSError, ValueError, TypeError, ImportError):
        print(json.dumps({"status": "ERROR", "error_code": "web_audit_failed"}))
        return 2


if __name__ == "__main__": raise SystemExit(main())
