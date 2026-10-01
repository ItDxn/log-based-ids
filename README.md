# Log-Based Intrusion Detection Tool

A small Python tool that parses SSH authentication logs, detects suspicious
login patterns using rule-based logic, stores alerts in SQLite, and displays
them on a live web dashboard.

**Status:** actively in development. Core pipeline (log generation → parsing
→ detection → storage → dashboard) is working end to end. Planned next:
More detection rules, simulating attacks in real-time and live auto-refresh on the dashboard

## What it does

- Generates realistic sample SSH auth logs, including two attack patterns
- Parses raw log lines into structured events (timestamp, IP, username, result)
- Detects two types of suspicious activity:
  - **Brute force**: many failed logins from one IP in a short time window
  - **Distributed attack**: the same username targeted from many different
    IPs, low and slow enough to evade a simple rate threshold
- Persists alerts to a SQLite database
- Displays alerts on a Flask web dashboard

## Why these two detection rules

A single-IP rate threshold catches an obvious brute-force attempt, but an
attacker spreading attempts across many IPs can stay under that threshold
entirely. Tracking distinct IPs per username catches that second pattern,
which a naive count-based rule would miss. This is a common real-world
distinction between simple rate-limiting and actual credential-stuffing
detection.

## Running it

```bash
pip install -r requirements.txt

python3 generate_logs.py   # creates a sample auth log with attack patterns
python3 detect.py          # parses the log, runs both detectors, saves alerts
python3 dashboard.py       # starts the web dashboard
```

Then open `http://127.0.0.1:5000` in your browser.

## Project structure

```
generate_logs.py   # creates realistic fake SSH auth log data
parser.py           # regex-based parsing of raw log lines into structured events
detect.py            # rule-based detection engine (brute force + distributed attack)
storage.py           # SQLite persistence layer
dashboard.py         # Flask web dashboard
```

## Known limitations / next steps

- Detection thresholds are fixed constants rather than configurable
- The distributed-attack rule can flag a legitimate one-off failed login
  alongside real attack IPs, since it doesn't yet weight by failure count
  per IP
- No automated tests yet
- Dashboard does not currently auto-refresh
