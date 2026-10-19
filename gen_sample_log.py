"""gen_sample_log.py - generate a realistic fake auth.log for testing the detector.

Scenarios (all IPs are RFC 5737 / private ranges, nothing real):
  1. Brute force  : 203.0.113.50 hammers 'root' (40 attempts, ~2s apart)
  2. Password spray: 198.51.100.23 tries 12 usernames, a few passes each, slowly
  3. Compromise   : 203.0.113.77 fails 8x on 'imane' then succeeds
  4. Legit        : 192.168.1.10 'imane' logs in normally (one typo)

Usage: python gen_sample_log.py > samples/auth.log
"""
import random
from datetime import datetime, timedelta

random.seed(42)  # reproducible
HOST = "kali"
START = datetime(2026, 10, 19, 8, 0, 0)
events = []  # (datetime, message)


def add(ts, msg):
    events.append((ts, f"sshd[{random.randint(1000, 9999)}]: {msg}"))


def failed(ts, user, ip, valid=True):
    port = random.randint(30000, 65000)
    if not valid:
        add(ts, f"Invalid user {user} from {ip} port {port}")
        add(ts, f"Failed password for invalid user {user} from {ip} port {port} ssh2")
    else:
        add(ts, f"Failed password for {user} from {ip} port {port} ssh2")


def accepted(ts, user, ip):
    add(ts, f"Accepted password for {user} from {ip} port {random.randint(30000, 65000)} ssh2")


# 1) brute force on root
t = START + timedelta(minutes=15)
for _ in range(40):
    failed(t, "root", "203.0.113.50")
    t += timedelta(seconds=random.randint(1, 3))

# 2) password spray (many users, few tries each, spread out)
users = ["admin", "test", "oracle", "postgres", "ubuntu", "git", "ftp", "user", "guest", "pi", "deploy", "backup"]
t = START + timedelta(minutes=40)
for _ in range(3):
    for u in users:
        failed(t, u, "198.51.100.23", valid=False)
        t += timedelta(seconds=random.randint(15, 25))

# 3) compromise: failures then success
t = START + timedelta(hours=1, minutes=30)
for _ in range(8):
    failed(t, "imane", "203.0.113.77")
    t += timedelta(seconds=random.randint(2, 5))
accepted(t, "imane", "203.0.113.77")

# 4) legit user
for h, m in ((8, 5), (11, 20), (14, 2)):
    ts = START.replace(hour=h, minute=m)
    if (h, m) == (11, 20):
        failed(ts, "imane", "192.168.1.10")  # typo
        ts += timedelta(seconds=7)
    accepted(ts, "imane", "192.168.1.10")

# noise: unrelated non-sshd lines must be ignored by the parser
noise = [(START + timedelta(minutes=i * 9), f"CRON[{random.randint(100, 999)}]: pam_unix(cron:session): session opened for user root")
         for i in range(10)]

for ts, msg in sorted(events + noise):
    print(f"{ts.strftime('%b')} {ts.day:>2} {ts.strftime('%H:%M:%S')} {HOST} {msg}")
