from datetime import datetime, timedelta
from detect import detect_brute_force, detect_dist_attack

BASE = datetime(2026, 9, 3, 9, 0, 0)
DISTERIOR_IPS = [
        "198.52.100.11", "198.52.100.24", "198.52.100.37",
        "198.52.100.42", "198.51.100.58"
    ]

#Failed login
def fail(user, ip, seconds):
    return {
        "username": user,
        "ip": ip,
        "timestamp": BASE + timedelta(seconds=seconds),
        "success": False,
    }

#Successful login
def success(user, ip, seconds):
    return {
        "username": user,
        "ip": ip,
        "timestamp": BASE + timedelta(seconds=seconds),
        "success": True,
    }

#6 failures from one IP, 2 seconds apart (should trigger alert)
def test_brute_force_fast_failures_alert():
    events = [fail("root", "203.0.113.7", i * 2) for i in range(6)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "203.0.113.7"

#6 failures from one IP, 5 minutes apart (shouldn't trigger alert)
def test_brute_force_slow_failures_no_alert():
    events = [fail("root", "203.0.113.7", i * 300) for i in range(6)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 0

#Tests if brute force flagged from successful logins (shouldn't trigger)
def test_brute_force_successful_no_alert():
    events = [success("root", "203.0.113.7", i * 2) for i in range(6)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 0

#Tests brute force events for default window against widened window
def test_brute_force_respects_custom_window():
    events = [fail("root", "203.0.113.7", i * 300) for i in range(6)]
    assert len(detect_brute_force(events)) == 0                       
    assert len(detect_brute_force(events, window_seconds=3600)) == 1

#Tests for one username failing from 5 different IPs minutes apart (should trigger)
def test_distributed_attack_alert():
    events = [fail("svc-backup", DISTERIOR_IPS[i-1], i * 180) for i in range(5)]
    alerts = detect_dist_attack(events)
    assert len(alerts) == 1

#Tests for one username failing from 5 different IPs hours apart (shouldn't trigger)
def test_distributed_attack_slow_failures_no_alert():
    events = [fail("svc-backup", DISTERIOR_IPS[i-1], i * 3600) for i in range(5)]
    alerts = detect_dist_attack(events)
    assert len(alerts) == 0

#Tests if distributed attack detection counts a brute-force pattern
def test_distributed_attack_single_ip_no_alert():
    events = [fail("svc-backup", "203.0.113.7", i * 2) for i in range(5)]
    alerts = detect_dist_attack(events)
    assert len(alerts) == 0