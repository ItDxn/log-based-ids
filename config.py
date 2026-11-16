import json
from pathlib import Path

DEFAULTS = {
    "brute_force_threshold": 5,
    "brute_force_window_seconds": 60,
    "dist_ip_threshold": 4,
    "dist_window_seconds": 3600,
}

CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config():
    config = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH) as f:
            user_settings = json.load(f)
            config.update(user_settings)
    except FileNotFoundError:
        pass                           
    return config

if __name__ == "__main__":
    print(load_config())