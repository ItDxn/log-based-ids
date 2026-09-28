from collections import defaultdict
from parser import parse_file

FAILURE_THRESHOLD = 5      # flag if this many failures happen...
WINDOW_SECONDS = 60        # ...within this many seconds


#Detecting Brute Force Attempts
def detect_brute_force(events):
    failures_by_ip = defaultdict(list)
    alerts = []
    already_alerted = set()

    for event in events:
        if event["success"]:
            continue

        ip = event["ip"]
        ts = event["timestamp"]

        # Add this failure, then drop any that are older than our window
        failures_by_ip[ip].append(ts)
        cutoff = ts.timestamp() - WINDOW_SECONDS
        failures_by_ip[ip] = [t for t in failures_by_ip[ip] if t.timestamp() >= cutoff]

        if len(failures_by_ip[ip]) >= FAILURE_THRESHOLD and ip not in already_alerted:
            alerts.append({
                "type": "brute_force",
                "ip": ip,
                "count": len(failures_by_ip[ip]),
                "window_seconds": WINDOW_SECONDS,
                "first_seen": failures_by_ip[ip][0],
                "last_seen": ts,
            })
            already_alerted.add(ip)

    return alerts


#Detecting Distributed Attacks
def detect_dist_attack(events):
    ips_by_user = defaultdict(set)
    alerts = []
    already_alerted = set()

    for event in events:
        if event["success"]:
            continue

        user = event["username"]
        ip = event["ip"]
        ts = event["timestamp"]

        ips_by_user[user].add(ip)

        if len(ips_by_user[user]) >= 4 and user not in already_alerted:
            alerts.append({
                "type": "distributed_attack",
                "ip": ", ".join(ips_by_user[user]),
                "count": len(ips_by_user[user]),
                "first_seen": ts,
                "last_seen": ts,
            })
            already_alerted.add(user)

    return alerts


if __name__ == "__main__":
    from storage import init_db, save_alert
    init_db()

    events = parse_file("sample_auth.log")

    brute_force_alerts = detect_brute_force(events)
    dist_alerts = detect_dist_attack(events)
    all_alerts = brute_force_alerts + dist_alerts

    print(f"Checked {len(events)} events, found {len(all_alerts)} alert(s):\n")
    for a in all_alerts:
        save_alert(a)
        print(f"[{a['type']}] {a['ip']}: {a['count']}")