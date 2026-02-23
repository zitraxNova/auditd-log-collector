import json
import re
from datetime import datetime

AUDIT_LOG_PATH = "/var/log/audit/audit.log"
OUTPUT_FILE = "audit_output.json"
FILTER_TYPES = {"SYSCALL"}

def parse_audit_line(line: str) -> dict | None:
    type_match = re.search(r"type=(\w+)", line)
    msg_match = re.search(r"audit\((\d+\.\d+):(\d+)\)", line)
    if not type_match or not msg_match:
        return None

    event_type = type_match.group(1)
    timestamp = float(msg_match.group(1))
    event_id = msg_match.group(2)
    if event_type not in FILTER_TYPES:
        return None

    fields = {}
    parts = re.findall(r'(\w+)=("[^"]*"|\S+)', line)
    for key, value in parts:
        fields[key] = value.strip('"')

    return {
        "event_type": event_type,
        "event_id": event_id,
        "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
        "raw": line.strip(),
        "fields": fields
    }


def collect_logs():
    parsed_events = []
    f = open(AUDIT_LOG_PATH, "r")
    for line in f:
        event = parse_audit_line(line)
        if event:
            parsed_events.append(event)
    return parsed_events


def save_to_file(events: list):
    f = open(OUTPUT_FILE, "w")
    json.dump(events, f, indent=4)


if __name__ == "__main__":
    events = collect_logs()
    save_to_file(events)
    print(f"Saved {len(events)} events to {OUTPUT_FILE}")