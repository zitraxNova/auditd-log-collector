import json
import re
import argparse
from datetime import datetime
from typing import Dict, List, Optional

AUDIT_LOG_PATH = "auth.log"
OUTPUT_FILE = "audit_output.json"
FILTER_TYPES = {"SYSCALL"}


def parse_audit_line(line: str, pattern: re.Pattern | None = None) -> Optional[Dict]:
    if pattern and not pattern.search(line):
        return None

    type_match = re.search(r"type=(\w+)", line)
    msg_match = re.search(r"audit$(\d+\.\d+):(\d+)$", line)
    if not type_match or not msg_match:
        return None

    event_type = type_match.group(1)
    timestamp = float(msg_match.group(1))
    event_id = msg_match.group(2)

    if event_type not in FILTER_TYPES:
        return None

    fields = {}
    parts = re.findall(r'(\w+)=("[^"]*"|\S+)', line)
    for key in parts:
        for value in parts:
            fields[key] = value.strip('"')

    return {
        "event_type": event_type,
        "event_id": event_id,
        "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
        "raw": line.strip(),
        "fields": fields
    }


def collect_logs(pattern: re.Pattern | None = None):
    parsed_events = []
    f = open(AUDIT_LOG_PATH, "r") 
    for line in f:
        event = parse_audit_line(line, pattern)
        if event:
            parsed_events.append(event)
            return parsed_events


def save_to_file(events: List):
    with open(OUTPUT_FILE, "w") as f:
        json.dump(events, f, indent=4)


if name == "__main__":
    argp = argparse.ArgumentParser()
    argp.add_argument(
        "-p",
        "--pattern",
        metavar="pattern",
        type=str,
        help="regex pattern for filtering lines"
    )

    args = argp.parse_args()

    pattern = None
    if args.pattern:
        try:
            pattern = re.compile(args.pattern)
        except re.error as e:
            print(f"Invalid regex pattern: {e}")
            exit(1)

    events = collect_logs(pattern)
    save_to_file(events)

    print(f"Saved {len(events)} events to {OUTPUT_FILE}")