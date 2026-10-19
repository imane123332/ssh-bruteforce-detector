from parser import parse_file
from detectors import run_all

events = list(parse_file("samples/auth.log", 2026))
for a in run_all(events):
    print(f'{a["type"]:<11} {a["ip"]:<15} count={a["count"]:<3} {a["mitre"]} {a["severity"]}')
