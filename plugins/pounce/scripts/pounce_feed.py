#!/usr/bin/env python3
"""Refresh or export the local Pounce intelligence feed."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pounce_intel import export_intelligence_feed, state_dir, sync_public_intelligence


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Refresh or export the local Pounce intelligence feed.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sync_parser = subparsers.add_parser("sync", help="Refresh the local intelligence feed from public sources.")
    sync_parser.add_argument("--output", help="Optional path to also write the refreshed normalized feed JSON.")

    export_parser = subparsers.add_parser("export", help="Write the current normalized feed JSON artifact.")
    export_parser.add_argument("--output", help="Optional output path. Defaults to stdout.")

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "sync":
        feed = sync_public_intelligence()
        if args.output:
            output_path = Path(args.output).expanduser().resolve()
            output_path.write_text(json.dumps(feed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"Wrote normalized feed: {output_path}")
        print(f"Updated local intelligence state: {state_dir()}")
        print(f"Feed items: {len(feed.get('items', []))}")
        return 0

    feed = export_intelligence_feed(output_path=args.output)
    if args.output:
        print(f"Wrote normalized feed: {Path(args.output).expanduser().resolve()}")
    else:
        print(json.dumps(feed, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
