"""Read explicit saved observations; print fixed-scope JSON without live actions."""
import argparse
import json
import sys
from pathlib import Path
from config_audit.kisa_2026 import PROFILE, assess
from config_audit.reporting import unique_object


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.input and args.input.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('input_too_large')
        packet = json.loads(args.input.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_object) if args.input else {'profile': PROFILE}
        result = assess(packet)
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, TypeError):
        print('kisa_input_invalid', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
