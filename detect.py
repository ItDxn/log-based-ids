from collections import defaultdict
from parser import parse_file

# Brute force conditions
BRUTE_FAILURE_THRESHOLD = 5
BRUTE_WINDOW_SECONDS = 60

# Distributed attack conditions
DIST_IP_THRESHOLD = 4
DIST_WINDOW_SECONDS = 3600


#Detecting brute force attempts
def detect_brute_force(events):
    failures_by_ip = defaultdict(list)
    alerts = []
    already_alerted = set()

    for event in events:
        if event["success"]:
            continue

        ip = event["ip"]
        ts = event["timestamp"]

        # Add failure and drop any older than window
        failures_by_ip[ip].append(ts)
        cutoff = ts.timestamp() - BRUTE_WINDOW_SECONDS
        failures_by_ip[ip] = [t for t in failures_by_ip[ip] if t.timestamp() >= cutoff]

        if len(failures_by_ip[ip]) >= BRUTE_FAILURE_THRESHOLD and ip not in already_alerted:
            alerts.append({
                "type": "brute_force",
                "ip": ip,
                "count": len(failures_by_ip[ip]),
                "window_seconds": BRUTE_WINDOW_SECONDS,
                "first_seen": failures_by_ip[ip][0],
                "last_seen": ts,
            })
            already_alerted.add(ip)

    return alerts


# Detecting distributed attacks
def detect_dist_attack(events):
    failures_by_user = defaultdict(list)
    alerts = []
    already_alerted = set()

    for event in events:
        if event["success"]:
            continue

        user = event["username"]
        ip = event["ip"]
        ts = event["timestamp"]

        failures_by_user[user].append((ts, ip))
        cutoff = ts.timestamp() - DIST_WINDOW_SECONDS
        failures_by_user[user] = [(t, i) for t, i in failures_by_user[user] if t.timestamp() >= cutoff]

        window = failures_by_user[user]
        distinct_ips = {i for t, i in window}

        if len(distinct_ips) >= DIST_IP_THRESHOLD and user not in already_alerted:
            alerts.append({
                "type": "distributed_attack",
                "ip": ", ".join(sorted(distinct_ips)),
                "count": len(distinct_ips),
                "first_seen": window[0][0],
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