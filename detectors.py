"""detectors.py - detection rules working on the events produced by parser.py.

Every detector takes `events` (list of dicts from parse_file) and returns a list
of ALERT dicts shaped like:

    {"type": "bruteforce", "ip": "203.0.113.50", "count": 40,
     "first_seen": datetime, "last_seen": datetime,
     "mitre": "T1110.001", "severity": "high"}

Expected results on samples/auth.log (defaults):
    bruteforce : 203.0.113.50, 203.0.113.77, 198.51.100.23   (NOT 192.168.1.10)
    spray      : 198.51.100.23                                (12 distinct users)
    compromise : 203.0.113.77                                 (accepted after failures)
"""
from collections import defaultdict, deque
from datetime import timedelta


def detect_bruteforce(events, threshold=5, window_minutes=10):
    """Flag an IP with >= `threshold` failed logins inside any `window_minutes` window."""
    alerts = []
    by_ip = defaultdict(list)

    # Keep only failed logins and group their timestamps by IP.
    for ev in events:
        if ev["status"] == "failed":
            by_ip[ev["ip"]].append(ev["ts"])

    for ip, timestamps in by_ip.items():
        timestamps.sort()
        window = deque()

        for ts in timestamps:
            window.append(ts)

            # Forget attempts older than the window.
            while window and window[0] < ts - timedelta(minutes=window_minutes):
                window.popleft()

            if len(window) >= threshold:
                alerts.append({
                    "type": "bruteforce",
                    "ip": ip,
                    "count": len(timestamps),
                    "first_seen": timestamps[0],
                    "last_seen": timestamps[-1],
                    "mitre": "T1110.001",
                    "severity": "high",
                })
                break  # one alert per IP

    return alerts


def detect_spray(events, min_users=5):
    """Flag an IP that tried `min_users` or more distinct usernames."""
    alerts = []
    users_by_ip = defaultdict(set)
    times_by_ip = defaultdict(list)

    for ev in events:
        if ev["status"] == "failed":
            users_by_ip[ev["ip"]].add(ev["user"])
            times_by_ip[ev["ip"]].append(ev["ts"])

    for ip, users in users_by_ip.items():
        if len(users) >= min_users:
            alerts.append({
                "type": "spray",
                "ip": ip,
                "count": len(users),
                "first_seen": min(times_by_ip[ip]),
                "last_seen": max(times_by_ip[ip]),
                "mitre": "T1110.003",
                "severity": "high",
            })

    return alerts


def detect_compromise(events, flagged_ips):
    """Flag a successful login from an IP already flagged, after failed attempts."""
    alerts = []
    failures_by_ip = defaultdict(list)

    for ev in events:
        if ev["status"] == "failed" and ev["ip"] in flagged_ips:
            failures_by_ip[ev["ip"]].append(ev["ts"])

    for ev in events:
        if ev["status"] != "accepted":
            continue

        ip = ev["ip"]
        if ip not in flagged_ips:
            continue

        previous_failures = [ts for ts in failures_by_ip[ip] if ts < ev["ts"]]

        if previous_failures:
            alerts.append({
                "type": "compromise",
                "ip": ip,
                "count": len(previous_failures),
                "first_seen": min(previous_failures),
                "last_seen": ev["ts"],
                "mitre": "T1078",
                "severity": "critical",
            })

    return alerts


def run_all(events, threshold=5, window_minutes=10, min_users=5):
    """Run every detector and return one combined list of alerts."""
    brute = detect_bruteforce(events, threshold, window_minutes)
    spray = detect_spray(events, min_users)

    flagged = {a["ip"] for a in brute} | {a["ip"] for a in spray}
    comp = detect_compromise(events, flagged)

    return brute + spray + comp
