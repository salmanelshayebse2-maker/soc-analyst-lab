import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from .core import ROOT, decode_command, detect, load_rules, parse_events, reference, verify_manifest, write_results


def main():
    parser = argparse.ArgumentParser(description="Offline synthetic Windows investigation lab")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Parse evidence and write detections and timeline")
    run.add_argument("--input", type=Path, default=ROOT / "data/windows-events.xml")
    run.add_argument("--rules", type=Path, default=ROOT / "rules")
    run.add_argument("--out", type=Path, default=ROOT / "results")
    sub.add_parser("verify", help="Check bundled evidence SHA-256 manifest")
    show = sub.add_parser("show", help="Inspect one event; optionally decode PowerShell as text")
    show.add_argument("reference")
    show.add_argument("--decode", action="store_true")
    show.add_argument("--input", type=Path, default=ROOT / "data/windows-events.xml")
    args = parser.parse_args()
    try:
        if args.command == "verify":
            result = verify_manifest()
            print(f"PASS: {len(result['sha256'])} evidence file(s) match SHA-256 manifest")
        elif args.command == "run":
            events = parse_events(args.input)
            if not events:
                raise ValueError("Input contains no events")
            alerts = detect(events, load_rules(args.rules))
            # Prevent output files from replacing either input or rule definitions.
            protected = [args.input.resolve(), *[p.resolve() for p in args.rules.glob('*.json')]]
            if any((args.out / name).resolve() in protected for name in ('alerts.json', 'normalized.jsonl', 'timeline.csv', 'summary.md')):
                raise ValueError("Output would overwrite input or rules")
            write_results(events, alerts, args.out)
            print(f"Processed {len(events)} events; generated {len(alerts)} alerts -> {args.out}")
        else:
            event = next((e for e in parse_events(args.input) if reference(e) == args.reference), None)
            if event is None:
                raise ValueError("Event reference not found")
            print(json.dumps(event, indent=2))
            if args.decode:
                print("\nDECODED TEXT ONLY (never executed):")
                print(decode_command(event["EventData"].get("CommandLine", "")))
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
