# Log-Based Intrusion Detection Tool

A small Python tool that parses SSH authentication logs, detects suspicious
login patterns using rule-based logic, stores alerts in SQLite, and displays
them on a live web dashboard.

**Status:** actively in development. Core pipeline (log generation → parsing
→ detection → storage → dashboard) is working end to end. Planned next:
More detection rules, simulating attacks in real-time and live auto-refresh on the dashboard.

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

## Running the tests

python -m pytest

The tests cover both detection rules, including cases that should *not*
trigger alerts (slow failures, successful logins, one IP failing repeatedly).

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
- No automated tests yet

## Update log

- 01/10/2026: First commit.
- 20/10/2026: My first version had no time window, so slow and harmless failures from different 
devices can look like an attack. I reproduced it in the generator added a sliding window, and verified both cases.
Also, I updated the generator so the logs generate chronologically because my method before did not work.
- 10/11/2026: Added a simple auto-refresh to the dashboard to allow it to keep updating while new attacks get detected.
Shown extra columns on the dashboard to give the user more info about the attack.
- 15/11/2026: Added pytest tests for both detection rules in detect.py and a requirements.txt file.