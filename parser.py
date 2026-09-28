import re
from datetime import datetime

# This pattern matches both "Failed password" and "Accepted password" lines.
# The (?P<name>...) parts are "capture groups" -- named slots we pull out.
LOG_PATTERN = re.compile(
    r"(?P<month_day_time>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+password\s+for\s+"
    r"(?P<username>\S+)\s+from\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+\d+"
)

def parse_line(line, year=2026):
    """Try to parse one log line. Returns a dict, or None if it doesn't match."""
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    # Log lines don't include the year, so we add it ourselves.
    ts_str = f"{year} {match.group('month_day_time')}"
    timestamp = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")

    return {
        "timestamp": timestamp,
        "username": match.group("username"),
        "ip": match.group("ip"),
        "success": match.group("result") == "Accepted",
    }

def parse_file(path):
    """Parse every line in a log file, skipping any that don't match."""
    events = []
    with open(path) as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events

if __name__ == "__main__":
    events = parse_file("sample_auth.log")
    print(f"Parsed {len(events)} events\n")
    print("First 5 events:")
    for e in events[:5]:
        print(e)
