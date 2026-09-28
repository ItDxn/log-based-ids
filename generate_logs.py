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
 
    # --- Normal traffic across the morning ---
    for _ in range(15):
        t += timedelta(minutes=random.randint(2, 20))
        user = random.choice(USERNAMES)
        ip = random.choice(NORMAL_IPS)
        port = random.randint(40000, 60000)
        # occasionally someone mistypes their password once, then gets in
        if random.random() < 0.2:
            lines.append(log_line(t, "fail", user, ip, port))
            t += timedelta(seconds=2)
        lines.append(log_line(t, "success", user, ip, port))
 
    # === Brute-force Attack ===
    attack_start = start + timedelta(hours=1, minutes=30)
    t = attack_start
    for _ in range(40):
        t += timedelta(seconds=random.uniform(0.5, 2))
        port = random.randint(40000, 60000)
        lines.append(log_line(t, "fail", "root", ATTACKER_IP, port))

    # === Distributed Attack ===
 
    # sort everything into time order, like a real log file would be
    lines_with_time = []
    for line in lines:
        lines_with_time.append(line)
 
    return lines_with_time
 
if __name__ == "__main__":
    lines = generate()
    with open("sample_auth.log", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} log lines to sample_auth.log")