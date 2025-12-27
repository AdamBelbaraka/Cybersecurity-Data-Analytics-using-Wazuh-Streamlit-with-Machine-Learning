#!/usr/bin/env python3
"""
Convert Wazuh-style JSON Lines logs to CSV.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import pandas as pd


INPUT_RELATIVE = os.path.join("data", "logs_simules.jsonl")
OUTPUT_RELATIVE = os.path.join("data", "logs_simules.csv")


COLUMNS = [
    "timestamp",
    "agent_id",
    "agent_name",
    "agent_ip",
    "os_name",
    "os_version",
    "os_platform",
    "manager_name",
    "manager_ip",
    "location",
    "rule_id",
    "rule_level",
    "rule_description",
    "rule_groups",
    "decoder_name",
    "srcip",
    "dstip",
    "srcport",
    "dstport",
    "protocol",
    "user",
    "process",
    "command",
    "status",
    "full_log",
    "severity",
    "attack_type",
]


def get_nested(event: Dict[str, Any], path: str) -> Optional[Any]:
    current: Any = event
    for key in path.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def resolve_path(relative_path: str) -> str:
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(base_dir, relative_path)


def ensure_data_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


def build_row(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp": get_nested(event, "@timestamp"),
        "agent_id": get_nested(event, "agent.id"),
        "agent_name": get_nested(event, "agent.name"),
        "agent_ip": get_nested(event, "agent.ip"),
        "os_name": get_nested(event, "agent.os.name"),
        "os_version": get_nested(event, "agent.os.version"),
        "os_platform": get_nested(event, "agent.os.platform"),
        "manager_name": get_nested(event, "manager.name"),
        "manager_ip": get_nested(event, "manager.ip"),
        "location": get_nested(event, "location"),
        "rule_id": get_nested(event, "rule.id"),
        "rule_level": get_nested(event, "rule.level"),
        "rule_description": get_nested(event, "rule.description"),
        "rule_groups": get_nested(event, "rule.groups"),
        "decoder_name": get_nested(event, "decoder.name"),
        "srcip": get_nested(event, "data.srcip"),
        "dstip": get_nested(event, "data.dstip"),
        "srcport": get_nested(event, "data.srcport"),
        "dstport": get_nested(event, "data.dstport"),
        "protocol": get_nested(event, "data.protocol"),
        "user": get_nested(event, "data.user"),
        "process": get_nested(event, "data.process"),
        "command": get_nested(event, "data.command"),
        "status": get_nested(event, "data.status"),
        "full_log": get_nested(event, "full_log"),
        "severity": get_nested(event, "ml_labels.severity"),
        "attack_type": get_nested(event, "ml_labels.attack_type"),
    }


def main() -> None:
    input_path = resolve_path(INPUT_RELATIVE)
    output_path = resolve_path(OUTPUT_RELATIVE)
    ensure_data_dir(output_path)

    rows: List[Dict[str, Any]] = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows.append(build_row(event))

    df = pd.DataFrame(rows, columns=COLUMNS)
    df.to_csv(output_path, index=False)

    print(f"Converted {len(df)} rows to {output_path}")


if __name__ == "__main__":
    main()
