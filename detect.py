from collections import defaultdict
from parser import parse_file
from config import load_config

#Detecting brute force attempts
def detect_brute_force(events, threshold=5, window_seconds=60):
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
        cutoff = ts.timestamp() - window_seconds
        failures_by_ip[ip] = [t for t in failures_by_ip[ip] if t.timestamp() >= cutoff]

        if len(failures_by_ip[ip]) >= threshold and ip not in already_alerted:
            alerts.append({
                "type": "brute_force",
                "ip": ip,
                "count": len(failures_by_ip[ip]),
                "window_seconds": window_seconds,
                "first_seen": failures_by_ip[ip][0],
                "last_seen": ts,
            })
            already_alerted.add(ip)

    return alerts


# Detecting distributed attacks
def detect_dist_attack(events, ip_threshold=4, window_seconds=3600):
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
        cutoff = ts.timestamp() - window_seconds
        failures_by_user[user] = [(t, i) for t, i in failures_by_user[user] if t.timestamp() >= cutoff]

        window = failures_by_user[user]
        distinct_ips = {i for t, i in window}

        if len(distinct_ips) >= ip_threshold and user not in already_alerted:
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
    config = load_config()

    brute_force_alerts = detect_brute_force(
        events,
        threshold=config["brute_force_threshold"],
        window_seconds=config["brute_force_window_seconds"],
    )

    dist_alerts = detect_dist_attack(
        events,
        ip_threshold=config["dist_ip_threshold"],
        window_seconds=config["dist_window_seconds"],
    )
    
    all_alerts = brute_force_alerts + dist_alerts

    print(f"Checked {len(events)} events, found {len(all_alerts)} alert(s):\n")
    for a in all_alerts:
        save_alert(a)
        print(f"[{a['type']}] {a['ip']}: {a['count']}")