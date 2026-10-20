import random
from datetime import datetime, timedelta
 
USERNAMES = ["daniel", "alice", "bob", "root", "admin", "svc-backup"]
NORMAL_IPS = ["10.0.0.5", "10.0.0.8", "192.168.1.20"]
ATTACKER_IP = "203.0.113.7"
 
def log_line(timestamp, event_type, username, ip, port):
    ts_str = timestamp.strftime("%b %e %H:%M:%S").replace("  ", " ")
    if event_type == "fail":
        return f"{ts_str} myserver sshd[1234]: Failed password for {username} from {ip} port {port} ssh2"
    else:
        return f"{ts_str} myserver sshd[1234]: Accepted password for {username} from {ip} port {port} ssh2"
 
def generate():
    lines = []
    start = datetime(2026, 9, 3, 9, 0, 0)
    t = start
 
    # === Normal traffic across the morning ===
    for _ in range(15):
        t += timedelta(hours=random.randint(0,1), minutes=random.randint(2, 20))
        user = random.choice(USERNAMES)
        ip = random.choice(NORMAL_IPS)
        port = random.randint(40000, 60000)
        # Mistypes
        if random.random() < 0.2:
            lines.append((t, log_line(t, "fail", user, ip, port)))
            t += timedelta(seconds=2)
        lines.append((t, log_line(t, "success", user, ip, port)))
 
    # === Brute-force Attack ===
    attack_start = start + timedelta(hours=1, minutes=30)
    t = attack_start
    for _ in range(40):
        t += timedelta(seconds=random.uniform(0.5, 2))
        port = random.randint(40000, 60000)
        lines.append((t, log_line(t, "fail", "root", ATTACKER_IP, port)))

    # === Distributed Attack ===
    t = start + timedelta(hours=3)
    target_user = "svc-backup"
    distributed_ips = [
        "198.51.100.11", "198.51.100.24", "198.51.100.37",
        "198.51.100.42", "198.51.100.58", "198.51.100.63",
    ]
    for ip in distributed_ips:
        t += timedelta(minutes=random.randint(3, 8))
        port = random.randint(40000, 60000)
        lines.append((t, log_line(t, "fail", target_user, ip, port)))
        #If IP tries a second time shortly after
        if random.random() < 0.3:
            t += timedelta(seconds=random.uniform(5, 15))
            lines.append((t, log_line(t, "fail", target_user, ip, port)))

    # === Distributed Error Check ===
    disterror_ips = [
        "198.52.100.11", "198.52.100.24", "198.52.100.37",
        "198.52.100.42"
    ]
    for ip in disterror_ips:
        t += timedelta(hours=random.randint(1,3))
        port = random.randint(40000, 60000)
        lines.append((t, log_line(t, "fail", "alice", ip, port)))
 
    # Sort everything into time order, like a real log file would be
    lines.sort(key=lambda pair: pair[0])
    return [line for ts, line in lines] 
 
if __name__ == "__main__":
    lines = generate()
    with open("sample_auth.log", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} log lines to sample_auth.log")