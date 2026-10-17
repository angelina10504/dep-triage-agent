"""Command line: python -m triage path/to/requirements.txt [--json]"""
from __future__ import annotations

import argparse
import json
import sys

from .scanner import scan


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan a requirements.txt against OSV advisories.")
    ap.add_argument("requirements", help="path to requirements.txt")
    ap.add_argument("--json", action="store_true", help="print the full result as JSON (all evidence)")
    args = ap.parse_args()

    with open(args.requirements) as f:
        result = scan(f.read())

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0

    print(f"\n{'PACKAGE':<14}{'CURRENT':<10}{'TARGET':<10}{'STATUS':<11}REASON")
    for p in result.plans:
        print(f"{p.package:<14}{p.current_version or '-':<10}{p.target_version or '-':<10}"
              f"{p.status.value:<11}{p.reason}")
    print("\nPer-advisory decisions:")
    for m in result.matches:
        print(f"  [{m.decision.value:<12}] {m.dependency_id:<28} {m.advisory_id:<22} {m.reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
