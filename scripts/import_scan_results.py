"""Import a saved sanitized scan without scanning, DNS or external enrichment."""
import argparse
from scanner.artifacts import load_scan_artifact


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    args = parser.parse_args(argv)
    try:
        result = load_scan_artifact(args.input)
        from db.save_scan_results import save_scan_results
        identifier = save_scan_results(result)
    except Exception as error:
        print("scan_import_failed:" + type(error).__name__)
        return 1
    print("Imported scan_id=" + str(identifier))
    print("Storage history: " + result.get("storage", {}).get("history_capability", "LEGACY_CURRENT_STATE_ONLY"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
