from parser import parse_line

def test_failed_valid_user():
    ev = parse_line("Oct 19 08:15:02 kali sshd[1234]: Failed password for root from 203.0.113.50 port 51000 ssh2", 2026)
    assert ev["status"] == "failed" and ev["user"] == "root" and ev["ip"] == "203.0.113.50"

def test_failed_invalid_user():
    ev = parse_line("Oct  9 08:15:02 kali sshd[1]: Failed password for invalid user admin from 198.51.100.23 port 40000 ssh2", 2026)
    assert ev["status"] == "failed" and ev["user"] == "admin"

def test_accepted():
    ev = parse_line("Oct 19 11:20:09 kali sshd[1]: Accepted password for imane from 192.168.1.10 port 50000 ssh2", 2026)
    assert ev["status"] == "accepted"

def test_iso_timestamp():
    ev = parse_line("2026-10-19T08:15:02.123456+01:00 kali sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2")
    assert ev["ts"].hour == 8

def test_irrelevant_and_malformed_lines():
    assert parse_line("Oct 19 08:15:02 kali CRON[1]: session opened", 2026) is None
    assert parse_line("garbage", 2026) is None
    assert parse_line("", 2026) is None
