from datetime import datetime, timedelta

from detectors import detect_bruteforce, detect_spray, detect_compromise, run_all
from parser import parse_file

T0 = datetime(2026, 10, 19, 8, 0, 0)


def ev(seconds, ip, user="root", status="failed"):
    """Build a fake parsed event `seconds` after T0."""
    return {"ts": T0 + timedelta(seconds=seconds), "host": "kali", "ip": ip,
            "user": user, "status": status, "method": "password"}


# ---------- brute force ----------
def test_bruteforce_flags_fast_failures():
    events = [ev(i * 5, "1.1.1.1") for i in range(6)]          # 6 failures in 25 s
    alerts = detect_bruteforce(events, threshold=5, window_minutes=10)
    assert len(alerts) == 1 and alerts[0]["ip"] == "1.1.1.1"
    assert alerts[0]["mitre"] == "T1110.001"


def test_bruteforce_ignores_slow_failures():
    events = [ev(i * 3600, "2.2.2.2") for i in range(6)]       # 1 failure per hour
    assert detect_bruteforce(events, threshold=5, window_minutes=10) == []


def test_bruteforce_ignores_legit_user_typo():
    events = [ev(0, "192.168.1.10", "imane"), ev(7, "192.168.1.10", "imane", "accepted")]
    assert detect_bruteforce(events) == []


def test_bruteforce_one_alert_per_ip():
    events = [ev(i, "1.1.1.1") for i in range(30)]
    assert len(detect_bruteforce(events)) == 1


def test_bruteforce_threshold_boundary():
    events = [ev(i, "1.1.1.1") for i in range(4)]              # 4 < 5
    assert detect_bruteforce(events, threshold=5) == []
    events.append(ev(4, "1.1.1.1"))                            # exactly 5
    assert len(detect_bruteforce(events, threshold=5)) == 1


# ---------- spray ----------
def test_spray_flags_many_usernames():
    users = ["a", "b", "c", "d", "e", "f"]
    events = [ev(i * 30, "3.3.3.3", u) for i, u in enumerate(users)]
    alerts = detect_spray(events, min_users=5)
    assert len(alerts) == 1 and alerts[0]["count"] == 6
    assert alerts[0]["mitre"] == "T1110.003"


def test_spray_ignores_single_username():
    events = [ev(i, "4.4.4.4", "root") for i in range(20)]
    assert detect_spray(events, min_users=5) == []


# ---------- compromise ----------
def test_compromise_after_failures():
    events = [ev(i, "5.5.5.5", "imane") for i in range(5)] + [ev(60, "5.5.5.5", "imane", "accepted")]
    alerts = detect_compromise(events, flagged_ips={"5.5.5.5"})
    assert len(alerts) == 1 and alerts[0]["severity"] == "critical"


def test_compromise_ignores_unflagged_ip():
    events = [ev(0, "6.6.6.6", "imane", "accepted")]
    assert detect_compromise(events, flagged_ips={"5.5.5.5"}) == []


def test_compromise_ignores_success_before_failures():
    events = [ev(0, "5.5.5.5", "imane", "accepted")] + [ev(10 + i, "5.5.5.5", "imane") for i in range(5)]
    assert detect_compromise(events, flagged_ips={"5.5.5.5"}) == []


# ---------- end to end on the sample log ----------
def test_sample_log_end_to_end():
    events = list(parse_file("samples/auth.log", 2026))
    alerts = run_all(events)
    brute = {a["ip"] for a in alerts if a["type"] == "bruteforce"}
    assert brute == {"203.0.113.50", "198.51.100.23", "203.0.113.77"}
    assert {a["ip"] for a in alerts if a["type"] == "spray"} == {"198.51.100.23"}
    assert {a["ip"] for a in alerts if a["type"] == "compromise"} == {"203.0.113.77"}
    assert all(a["ip"] != "192.168.1.10" for a in alerts)      # legit user never flagged
