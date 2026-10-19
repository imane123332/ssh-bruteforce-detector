"""analyzer.py - command-line entry point.

Usage:
    python analyzer.py --log samples/auth.log
    python analyzer.py --log samples/auth.log --threshold 3 --window 5 --json out.json
"""
import argparse
import json
from datetime import datetime

from parser import parse_file
from detectors import run_all


def build_args():
    p = argparse.ArgumentParser(description="Detect SSH brute-force, spraying and compromise in auth.log")
    p.add_argument("--log", required=True, help="path to the auth.log file")
    p.add_argument("--threshold", type=int, default=5, help="failed logins that trigger an alert (default 5)")
    p.add_argument("--window", type=int, default=10, help="window in minutes (default 10)")
    p.add_argument("--min-users", type=int, default=5, help="distinct usernames that trigger a spray alert (default 5)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year of the log (syslog lines have none)")
    p.add_argument("--json", metavar="FILE", help="also save the alerts to a JSON file")
    return p.parse_args()


def print_table(alerts):
    if not alerts:
        print("No suspicious activity found.")
        return
    header = f'{"TYPE":<11} {"IP":<16} {"COUNT":<6} {"FIRST SEEN":<20} {"LAST SEEN":<20} {"MITRE":<10} SEVERITY'
    print(header)
    print("-" * len(header))
    for a in alerts:
        first = a["first_seen"].strftime("%Y-%m-%d %H:%M:%S")
        last = a["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
        print(f'{a["type"]:<11} {a["ip"]:<16} {a["count"]:<6} {first:<20} {last:<20} {a["mitre"]:<10} {a["severity"]}')


def save_json(alerts, path):
    out = [{**a, "first_seen": a["first_seen"].isoformat(), "last_seen": a["last_seen"].isoformat()} for a in alerts]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"\nSaved {len(out)} alerts to {path}")


def main():
    args = build_args()
    events = list(parse_file(args.log, args.year))
    print(f"Parsed {len(events)} SSH events from {args.log}\n")
    alerts = run_all(events, args.threshold, args.window, args.min_users)
    print_table(alerts)
    if args.json:
        save_json(alerts, args.json)


if __name__ == "__main__":
    main()
