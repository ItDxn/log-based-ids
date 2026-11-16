# Log-Based Intrusion Detection Tool

A small Python tool that parses SSH authentication logs, detects suspicious
login patterns using rule-based logic, stores alerts in SQLite, and displays
them on a live web dashboard.

**Status:** actively in development. Core pipeline (log generation → parsing
→ detection → storage → dashboard) is working end to end. Planned next:
More detection rules, simulating attacks in real-time.

## What it does

- Generates realistic sample SSH auth logs, including two attack patterns
- Parses raw log lines into structured events (timestamp, IP, username, result)
- Detects two types of suspicious activity:
  - **Brute force**: many failed logins from one IP in a short time window
  - **Distributed attack**: the same username targeted from many different
    IPs, low and slow enough to evade a simple rate threshold
- Persists alerts to a SQLite database
- Displays alerts on a Flask web dashboard

## Design decisions

**Why these two detection rules:**

A single-IP rate threshold catches an obvious brute-force attempt, but an
attacker spreading attempts across many IPs can stay under that threshold. 
Tracking distinct IPs per username catches that, which a count-based rule 
would miss.

**Why a sliding window instead of a total count:**

My first distributed-attack rule counted distinct IPs per username over 
the whole log, so four harmless failures from four of someone’s own devices 
across a day looked like an attack. Adding a time window means only failures 
close together count. However, a very patient attacker that spaces attempts 
wider than the window, would evade the rule.

## Running it

```bash
pip install -r requirements.txt

python3 generate_logs.py   # creates a sample auth log with attack patterns
python3 detect.py          # parses the log, runs both detectors, saves alerts
python3 dashboard.py       # starts the web dashboard
```

Then open `http://127.0.0.1:5000` in your browser.

## Configuration

Detection settings live in `config.json`, so you can tune the rules without editing code:

| Setting | Default | Meaning |
|---|---|---|
| `brute_force_threshold` | 5 | Failed logins from one IP that trigger an alert |
| `brute_force_window_seconds` | 60 | Time window for that count |
| `dist_ip_threshold` | 4 | Distinct IPs failing against one username that trigger an alert |
| `dist_window_seconds` | 3600 | Time window for that count |

Missing settings fall back to these defaults.

## Running the tests

python -m pytest

The tests cover both detection rules, including cases that should *not*
trigger alerts (slow failures, successful logins, one IP failing repeatedly).

## Project structure

```
generate_logs.py   # creates realistic fake SSH auth log data
parser.py          # regex-based parsing of raw log lines into structured events
detect.py          # rule-based detection engine (brute force + distributed attack)
storage.py         # SQLite persistence layer
dashboard.py       # Flask web dashboard
test_detect.py     # pytest to check cases that do or don't trigger alerts
config.py          # applies user's custom theshold configurations
config.json        # holds user's configurations
requirements.txt   # contains libraries needed to run
```

## Known limitations / next steps

- Tested on simulated logs only, never on a real auth.log.
- The parser matches only Failed/Accepted password lines. Real logs also contain Failed password for invalid user ... lines, and public-key logins.
- IPv4 only, and the year is hardcoded in the parser.
- Re-running detect.py on the same log saves duplicate alerts.
- One alert per IP or username per run, and no authentication on the dashboard.

## Update log

- 01/10/2026: First commit.
- 20/10/2026: My first version had no time window, so slow and harmless failures from different 
devices can look like an attack. I reproduced it in the generator, added a sliding window, and verified both cases.
Also, I updated the generator so the logs generate chronologically because my method before did not work.
- 10/11/2026: Added a simple auto-refresh to the dashboard to allow it to keep updating while new attacks get detected.
added extra columns on the dashboard to give the user more info about the attack.
- 15/11/2026: Added pytest tests for both detection rules in detect.py and a requirements.txt file.
- 16/11/2026: Made detection thresholds configurable via config.json 