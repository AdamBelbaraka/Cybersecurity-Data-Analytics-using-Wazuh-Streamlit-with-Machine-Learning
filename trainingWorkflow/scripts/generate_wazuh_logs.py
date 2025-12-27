#!/usr/bin/env python3
"""
Generate realistic Wazuh-style events in JSON Lines format.

Output:
  - data/logs_simules.jsonl (default)
  - optionally split by scenario when CONFIG["split_by_scenario"] is True

Only standard library is used.
"""

from __future__ import annotations

import json
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Tuple


# =========================
# Configuration (EDIT HERE)
# =========================
CONFIG: Dict[str, object] = {
    # Core generation settings
    "seed": 42,  # Reproducibility
    "total_events": 10000,
    "benign_ratio": 0.8,  # 0.70 - 0.85 recommended
    "split_by_scenario": False,
    "output_dir": "data",
    "output_file": "logs_simules.jsonl",
    "enable_ml_labels": True,
    # Scenario toggles
    "enabled_scenarios": [
        "login_success",
        "web_access_normal",
        "file_access_normal",
        "brute_force_ssh",
        "privilege_escalation",
        "ddos",
        "phishing_email",
        "malware_execution",
    ],
    # Agent and manager metadata
    "manager": {"name": "wazuh-manager-01", "ip": "10.10.0.10"},
    "agents": [
        {"id": "001", "name": "web-01", "ip": "10.10.1.21", "os": {"name": "Ubuntu", "version": "22.04", "platform": "linux"}},
        {"id": "002", "name": "db-01", "ip": "10.10.1.30", "os": {"name": "CentOS", "version": "7", "platform": "linux"}},
        {"id": "003", "name": "win-01", "ip": "10.10.2.15", "os": {"name": "Windows", "version": "2019", "platform": "windows"}},
        {"id": "004", "name": "win-02", "ip": "10.10.2.22", "os": {"name": "Windows", "version": "10", "platform": "windows"}},
    ],
    # Network parameters
    "src_ip_ranges": ["192.168.1.", "172.16.5.", "203.0.113.", "198.51.100."],
    "internal_ip_ranges": ["10.10.1.", "10.10.2."],
    "ports": [22, 80, 443, 3389, 445, 53, 8080],
    "protocols": ["tcp", "udp"],
    "users": ["root", "admin", "ubuntu", "ec2-user", "alice", "bob", "svc_backup"],
    "processes": ["sshd", "apache2", "nginx", "powershell.exe", "cmd.exe", "svchost.exe", "python3"],
    # Ratio of attack types within the attack slice
    "attack_distribution": {
        "brute_force_ssh": 0.25,
        "privilege_escalation": 0.20,
        "ddos": 0.20,
        "phishing_email": 0.15,
        "malware_execution": 0.20,
    },
}

# Optional per-scenario toggles for quick comment-out
ENABLE_LOGIN_SUCCESS = True
ENABLE_WEB_ACCESS_NORMAL = True
ENABLE_FILE_ACCESS_NORMAL = True
ENABLE_BRUTEFORCE_SSH = True
ENABLE_PRIV_ESC = True
ENABLE_DDOS = True
ENABLE_PHISHING = True
ENABLE_MALWARE = True


# =========================
# Helpers
# =========================
def iso_utc(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def choose_agent(platform: str | None = None) -> Dict[str, object]:
    agents = CONFIG["agents"]  # type: ignore[assignment]
    if platform:
        filtered = [a for a in agents if a["os"]["platform"] == platform]
        return random.choice(filtered if filtered else agents)
    return random.choice(agents)


def rand_ip(prefixes: List[str]) -> str:
    prefix = random.choice(prefixes)
    return f"{prefix}{random.randint(1, 254)}"


def rand_port() -> int:
    return random.choice(CONFIG["ports"])  # type: ignore[arg-type]


def rand_protocol() -> str:
    return random.choice(CONFIG["protocols"])  # type: ignore[arg-type]


def build_base_event(ts: datetime, agent: Dict[str, object], location: str) -> Dict[str, object]:
    return {
        "@timestamp": iso_utc(ts),
        "agent": agent,
        "manager": CONFIG["manager"],
        "location": location,
    }


def add_ml_labels(event: Dict[str, object], attack_type: str) -> None:
    if not CONFIG["enable_ml_labels"]:
        return
    level = event["rule"]["level"]
    if level <= 3:
        severity = "low"
    elif level <= 7:
        severity = "medium"
    elif level <= 11:
        severity = "high"
    else:
        severity = "critical"
    event["ml_labels"] = {"severity": severity, "attack_type": attack_type}


def validate_event_schema(event: Dict[str, object]) -> bool:
    required = [
        "@timestamp",
        "agent",
        "manager",
        "rule",
        "decoder",
        "data",
        "location",
        "full_log",
    ]
    for key in required:
        if key not in event:
            return False
    agent_keys = ["id", "name", "ip", "os"]
    for key in agent_keys:
        if key not in event["agent"]:
            return False
    return True


# =========================
# Normal (Benign) Scenarios
# =========================
def generate_login_success(ts: datetime) -> Dict[str, object]:
    agent = choose_agent(platform="linux")
    srcip = rand_ip(CONFIG["src_ip_ranges"])  # type: ignore[arg-type]
    user = random.choice(CONFIG["users"])  # type: ignore[arg-type]
    event = build_base_event(ts, agent, location="/var/log/auth.log")
    event.update(
        {
            "rule": {"id": "5716", "level": 3, "description": "Successful SSH login", "groups": ["authentication_success", "ssh"]},
            "decoder": {"name": "sshd"},
            "data": {
                "srcip": srcip,
                "dstip": agent["ip"],
                "srcport": random.randint(1024, 65535),
                "dstport": 22,
                "protocol": "tcp",
                "user": user,
                "process": "sshd",
                "status": "Accepted password",
            },
            "full_log": f"Accepted password for {user} from {srcip} port {random.randint(1024,65535)} ssh2",
        }
    )
    add_ml_labels(event, "normal")
    return event


def generate_web_access_normal(ts: datetime) -> Dict[str, object]:
    agent = choose_agent(platform="linux")
    srcip = rand_ip(CONFIG["src_ip_ranges"])  # type: ignore[arg-type]
    method = random.choice(["GET", "POST", "HEAD"])
    uri = random.choice(["/", "/index.html", "/assets/app.js", "/login", "/health"])
    status_code = random.choice([200, 200, 200, 304, 301])
    event = build_base_event(ts, agent, location="/var/log/nginx/access.log")
    event.update(
        {
            "rule": {"id": "31102", "level": 2, "description": "Web access normal", "groups": ["web", "access"]},
            "decoder": {"name": "nginx"},
            "data": {
                "srcip": srcip,
                "dstip": agent["ip"],
                "srcport": random.randint(1024, 65535),
                "dstport": 80,
                "protocol": "tcp",
                "user": "-",
                "process": "nginx",
                "status": str(status_code),
                "command": f"{method} {uri} HTTP/1.1",
            },
            "full_log": f'{srcip} - - "{method} {uri} HTTP/1.1" {status_code} {random.randint(200, 2048)}',
        }
    )
    add_ml_labels(event, "normal")
    return event


def generate_file_access_normal(ts: datetime) -> Dict[str, object]:
    agent = choose_agent(platform=random.choice(["linux", "windows"]))
    user = random.choice(CONFIG["users"])  # type: ignore[arg-type]
    file_path = random.choice(
        ["/var/www/html/index.html", "/etc/cron.daily/backup", "C:\\Windows\\Temp\\tmp.log", "C:\\Users\\Public\\report.docx"]
    )
    location = "/var/log/audit/audit.log" if agent["os"]["platform"] == "linux" else "EventChannel"
    decoder = "auditd" if agent["os"]["platform"] == "linux" else "windows_eventchannel"
    event = build_base_event(ts, agent, location=location)
    event.update(
        {
            "rule": {"id": "80703", "level": 3, "description": "File access normal", "groups": ["file", "audit"]},
            "decoder": {"name": decoder},
            "data": {
                "srcip": agent["ip"],
                "dstip": agent["ip"],
                "srcport": 0,
                "dstport": 0,
                "protocol": "local",
                "user": user,
                "process": random.choice(CONFIG["processes"]),  # type: ignore[arg-type]
                "command": f"open {file_path}",
            },
            "full_log": f"File accessed by user {user}: {file_path}",
        }
    )
    add_ml_labels(event, "normal")
    return event


# =========================
# Attack Scenarios
# =========================
def generate_bruteforce_ssh(ts: datetime, srcip: str | None = None) -> Dict[str, object]:
    agent = choose_agent(platform="linux")
    srcip = srcip or rand_ip(CONFIG["src_ip_ranges"])  # type: ignore[arg-type]
    user = random.choice(CONFIG["users"])  # type: ignore[arg-type]
    event = build_base_event(ts, agent, location="/var/log/auth.log")
    event.update(
        {
            "rule": {"id": "5712", "level": 10, "description": "SSHD brute force attempt", "groups": ["authentication_failed", "ssh", "attack"]},
            "decoder": {"name": "sshd"},
            "data": {
                "srcip": srcip,
                "dstip": agent["ip"],
                "srcport": random.randint(1024, 65535),
                "dstport": 22,
                "protocol": "tcp",
                "user": user,
                "process": "sshd",
                "status": "Failed password",
            },
            "full_log": f"Failed password for invalid user {user} from {srcip} port {random.randint(1024,65535)} ssh2",
        }
    )
    add_ml_labels(event, "bruteforce")
    return event


def generate_privilege_escalation(ts: datetime) -> Dict[str, object]:
    agent = choose_agent(platform=random.choice(["linux", "windows"]))
    user = random.choice(CONFIG["users"])  # type: ignore[arg-type]
    if agent["os"]["platform"] == "linux":
        location = "/var/log/auth.log"
        decoder = "sudo"
        full_log = f"sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash"
        command = "sudo /bin/bash"
        rule_groups = ["sudo", "privilege_escalation", "attack"]
        rule_desc = "Possible privilege escalation via sudo"
    else:
        location = "EventChannel"
        decoder = "windows_eventchannel"
        full_log = f"Administrator privileges assigned to user {user}"
        command = "net localgroup administrators /add"
        rule_groups = ["windows", "privilege_escalation", "attack"]
        rule_desc = "Suspicious admin group modification"
    event = build_base_event(ts, agent, location=location)
    event.update(
        {
            "rule": {"id": "60122", "level": 12, "description": rule_desc, "groups": rule_groups},
            "decoder": {"name": decoder},
            "data": {
                "srcip": agent["ip"],
                "dstip": agent["ip"],
                "srcport": 0,
                "dstport": 0,
                "protocol": "local",
                "user": user,
                "process": random.choice(CONFIG["processes"]),  # type: ignore[arg-type]
                "command": command,
            },
            "full_log": full_log,
        }
    )
    add_ml_labels(event, "privilege_escalation")
    return event


def generate_ddos(ts: datetime, target_ip: str | None = None) -> Dict[str, object]:
    agent = choose_agent(platform="linux")
    srcip = rand_ip(CONFIG["src_ip_ranges"])  # type: ignore[arg-type]
    target_ip = target_ip or agent["ip"]
    dstport = random.choice([80, 443, 8080])
    event = build_base_event(ts, agent, location="/var/log/firewall.log")
    event.update(
        {
            "rule": {"id": "10110", "level": 11, "description": "Possible DDoS flood detected", "groups": ["network", "ddos", "attack"]},
            "decoder": {"name": "iptables"},
            "data": {
                "srcip": srcip,
                "dstip": target_ip,
                "srcport": random.randint(1024, 65535),
                "dstport": dstport,
                "protocol": random.choice(["tcp", "udp"]),
                "user": "-",
                "process": "kernel",
                "status": "SYN flood",
            },
            "full_log": f"IN=eth0 OUT= MAC=... SRC={srcip} DST={target_ip} LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=12345 PROTO=TCP SPT={random.randint(1024,65535)} DPT={dstport} SYN",
        }
    )
    add_ml_labels(event, "ddos")
    return event


def generate_phishing_email(ts: datetime) -> Dict[str, object]:
    agent = choose_agent(platform="windows")
    srcip = rand_ip(CONFIG["src_ip_ranges"])  # type: ignore[arg-type]
    sender = random.choice(["it-support@secure-mail.com", "alerts@banking-secure.com", "hr@company-portal.com"])
    subject = random.choice(
        ["Action Required: Password Reset", "Invoice #84723 Attached", "Verify your account now", "Security alert on your account"]
    )
    location = "EventChannel"
    event = build_base_event(ts, agent, location=location)
    event.update(
        {
            "rule": {"id": "92021", "level": 9, "description": "Phishing email indicators detected", "groups": ["email", "phishing", "attack"]},
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "srcip": srcip,
                "dstip": agent["ip"],
                "srcport": random.randint(1024, 65535),
                "dstport": 25,
                "protocol": "tcp",
                "user": random.choice(CONFIG["users"]),  # type: ignore[arg-type]
                "process": "outlook.exe",
                "command": f"email_subject={subject}",
                "status": f"sender={sender}",
            },
            "full_log": f"Suspicious email from {sender} to user inbox. Subject: {subject}. URL: hxxp://secure-login.example.com",
        }
    )
    add_ml_labels(event, "phishing")
    return event


def generate_malware_execution(ts: datetime) -> Dict[str, object]:
    agent = choose_agent(platform=random.choice(["linux", "windows"]))
    srcip = rand_ip(CONFIG["src_ip_ranges"])  # type: ignore[arg-type]
    if agent["os"]["platform"] == "linux":
        location = "/var/log/syslog"
        decoder = "syslog"
        process = "python3"
        command = "/tmp/cryptominer -o stratum+tcp://malicious.pool:3333"
        full_log = f"Process started: {process} {command}"
    else:
        location = "EventChannel"
        decoder = "windows_eventchannel"
        process = "powershell.exe"
        command = "powershell -EncodedCommand SQBFAFgAIA..."
        full_log = f"Suspicious process execution: {process} {command}"
    event = build_base_event(ts, agent, location=location)
    event.update(
        {
            "rule": {"id": "100201", "level": 13, "description": "Malware execution suspected", "groups": ["malware", "execution", "attack"]},
            "decoder": {"name": decoder},
            "data": {
                "srcip": srcip,
                "dstip": agent["ip"],
                "srcport": random.randint(1024, 65535),
                "dstport": rand_port(),
                "protocol": rand_protocol(),
                "user": random.choice(CONFIG["users"]),  # type: ignore[arg-type]
                "process": process,
                "command": command,
                "status": "execution",
            },
            "full_log": full_log,
        }
    )
    add_ml_labels(event, "malware")
    return event


# =========================
# Orchestration
# =========================
def generate_normal_events(count: int, start_ts: datetime) -> List[Dict[str, object]]:
    events: List[Dict[str, object]] = []
    generators = []
    if ENABLE_LOGIN_SUCCESS and "login_success" in CONFIG["enabled_scenarios"]:
        generators.append(generate_login_success)
    if ENABLE_WEB_ACCESS_NORMAL and "web_access_normal" in CONFIG["enabled_scenarios"]:
        generators.append(generate_web_access_normal)
    if ENABLE_FILE_ACCESS_NORMAL and "file_access_normal" in CONFIG["enabled_scenarios"]:
        generators.append(generate_file_access_normal)
    for i in range(count):
        ts = start_ts + timedelta(seconds=i)
        gen = random.choice(generators)
        events.append(gen(ts))
    return events


def generate_attack_events(count: int, start_ts: datetime) -> Dict[str, List[Dict[str, object]]]:
    attack_events: Dict[str, List[Dict[str, object]]] = {k: [] for k in CONFIG["attack_distribution"]}  # type: ignore[arg-type]
    distributions = CONFIG["attack_distribution"]  # type: ignore[assignment]
    scenarios = [k for k in distributions.keys() if k in CONFIG["enabled_scenarios"]]
    weights = [distributions[s] for s in scenarios]
    for i in range(count):
        ts = start_ts + timedelta(seconds=i)
        scenario = random.choices(scenarios, weights=weights, k=1)[0]
        if scenario == "brute_force_ssh" and ENABLE_BRUTEFORCE_SSH:
            attack_events[scenario].append(generate_bruteforce_ssh(ts))
        elif scenario == "privilege_escalation" and ENABLE_PRIV_ESC:
            attack_events[scenario].append(generate_privilege_escalation(ts))
        elif scenario == "ddos" and ENABLE_DDOS:
            attack_events[scenario].append(generate_ddos(ts))
        elif scenario == "phishing_email" and ENABLE_PHISHING:
            attack_events[scenario].append(generate_phishing_email(ts))
        elif scenario == "malware_execution" and ENABLE_MALWARE:
            attack_events[scenario].append(generate_malware_execution(ts))
    return attack_events


def write_events(path: str, events: Iterable[Dict[str, object]]) -> int:
    count = 0
    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            if validate_event_schema(ev):
                f.write(json.dumps(ev, ensure_ascii=True) + "\n")
                count += 1
    return count


def ensure_output_dir() -> str:
    out_dir = str(CONFIG["output_dir"])
    if not os.path.isabs(out_dir):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        out_dir = os.path.join(base_dir, out_dir)
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def main() -> None:
    random.seed(CONFIG["seed"])
    out_dir = ensure_output_dir()
    total = int(CONFIG["total_events"])
    benign = int(total * float(CONFIG["benign_ratio"]))
    attack = total - benign

    start_ts = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    normal_events = generate_normal_events(benign, start_ts)
    attack_events = generate_attack_events(attack, start_ts + timedelta(seconds=benign))

    summary: Dict[str, int] = {"normal": len(normal_events)}
    for scenario, evs in attack_events.items():
        summary[scenario] = len(evs)

    if CONFIG["split_by_scenario"]:
        normal_path = os.path.join(out_dir, "logs_normal.jsonl")
        write_events(normal_path, normal_events)
        for scenario, evs in attack_events.items():
            path = os.path.join(out_dir, f"logs_{scenario}.jsonl")
            write_events(path, evs)
    else:
        all_events: List[Dict[str, object]] = []
        for evs in attack_events.values():
            all_events.extend(evs)
        all_events.extend(normal_events)
        random.shuffle(all_events)
        output_path = os.path.join(out_dir, str(CONFIG["output_file"]))
        write_events(output_path, all_events)

    print("Generation summary:")
    for k in sorted(summary.keys()):
        print(f"- {k}: {summary[k]}")


if __name__ == "__main__":
    main()

# Example:
#   python generate_wazuh_logs.py
