"""parser.py - turn raw sshd lines from auth.log into normalized event dicts.

Event shape:
    {"ts": datetime, "host": str, "ip": str, "user": str,
     "status": "failed" | "accepted" | "invalid_user", "method": str | None}

Supports both timestamp styles:
    - classic syslog:  "Oct 19 08:15:02 kali sshd[1234]: ..."
    - ISO 8601:        "2026-10-19T08:15:02.123456+01:00 kali sshd[1234]: ..."

NOTE: "Failed password for invalid user X" and "Invalid user X" are logged as two
separate lines for the same attempt. Count only status == "failed" for failure
thresholds, otherwise you double count.
"""
import re
from datetime import datetime
from typing import Iterator, Optional

IP = r"[0-9a-fA-F:.]+"

# --- 1) outer syslog line: timestamp, host, sshd[pid]: message
LINE_RE = re.compile(
    r"^(?:(?P<ts_iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)"
    r"|(?P<ts_sys>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}))"
    r"\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# --- 2) message patterns
FAILED_RE = re.compile(
    rf"Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
    rf"(?:invalid user )?(?P<user>\S+) from (?P<ip>{IP}) port \d+"
)
ACCEPTED_RE = re.compile(
    rf"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>{IP}) port \d+"
)
INVALID_RE = re.compile(rf"Invalid user (?P<user>\S*) from (?P<ip>{IP})")


def _parse_ts(m: re.Match, year: int) -> datetime:
    if m.group("ts_iso"):
        # fromisoformat handles offsets on 3.11+; strip tz for older versions
        raw = m.group("ts_iso").replace("Z", "")
        raw = re.sub(r"[+-]\d{2}:\d{2}$", "", raw)
        return datetime.fromisoformat(raw)
    # syslog has no year -> we supply it (year rollover Dec->Jan not handled)
    return datetime.strptime(f"{year} {' '.join(m.group('ts_sys').split())}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: Optional[int] = None) -> Optional[dict]:
    """Return an event dict, or None if the line is not a relevant sshd event."""
    year = year or datetime.now().year
    m = LINE_RE.match(line.rstrip("\n"))
    if not m:
        return None
    msg = m.group("msg")

    for regex, status in ((FAILED_RE, "failed"), (ACCEPTED_RE, "accepted"), (INVALID_RE, "invalid_user")):
        e = regex.search(msg)
        if e:
            return {
                "ts": _parse_ts(m, year),
                "host": m.group("host"),
                "ip": e.group("ip"),
                "user": e.group("user"),
                "status": status,
                "method": e.groupdict().get("method"),
            }
    return None


def parse_file(path: str, year: Optional[int] = None) -> Iterator[dict]:
    """Yield events from a log file; malformed or irrelevant lines are skipped."""
    with open(path, "r", errors="replace") as f:
        for line in f:
            ev = parse_line(line, year)
            if ev:
                yield ev


if __name__ == "__main__":
    import sys
    for ev in parse_file(sys.argv[1]):
        print(ev)
