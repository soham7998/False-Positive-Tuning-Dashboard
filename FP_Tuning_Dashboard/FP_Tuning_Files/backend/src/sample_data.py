"""
Sample SOC alerts built from real Sigma rule definitions.
All alerts start as pending — no pre-decided verdicts.
"""

from datetime import datetime, timedelta
import random
from src.rule_library import CURATED_RULES, get_rule_by_name


def generate_sample_alerts() -> list:
    base_time = datetime.now() - timedelta(days=7)

    # FP-prone patterns — same rule + same entity repeating (realistic noise sources)
    fp_patterns = [
        {
            "rule": "Suspicious PowerShell Encoded Command",
            "ip": "10.0.1.50", "user": "admin_it_01",
            "process": "powershell.exe", "host": "IT-WORKSTATION-05",
        },
        {
            "rule": "Unusual Outbound Network Traffic",
            "ip": "10.0.5.20", "user": "svc_backup",
            "process": "backup_agent.exe", "host": "BACKUP-SRV-01",
        },
        {
            "rule": "Process Injection via CreateRemoteThread",
            "ip": "10.0.10.100", "user": "dev_team",
            "process": "devenv.exe", "host": "DEV-MACHINE-12",
        },
        {
            "rule": "Multiple Failed Login Attempts",
            "ip": "10.0.2.10", "user": "svc_monitor",
            "process": "monitor_agent.exe", "host": "MON-SRV-01",
        },
        {
            "rule": "Scheduled Task Creation via Schtasks",
            "ip": "10.0.3.15", "user": "svc_deploy",
            "process": "schtasks.exe", "host": "DEPLOY-SRV-02",
        },
    ]

    legit_users = ["john.doe", "alice.smith", "bob.johnson", "sarah.davis", "mike.wilson"]
    suspicious_users = ["unknown_user", "guest", "anonymous", "temp_admin"]

    alerts = []

    # Inject FP-prone patterns — 4 to 6 repeats each, all pending
    for pattern in fp_patterns:
        rule_meta = get_rule_by_name(pattern["rule"])
        severity = rule_meta.get("severity", "medium")
        technique = rule_meta.get("technique")
        tactic = rule_meta.get("tactic")

        for _ in range(random.randint(4, 6)):
            alert_time = base_time + timedelta(
                days=random.randint(0, 6),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
            )
            alerts.append({
                "alert_id": f"ALT-{len(alerts)+1:05d}",
                "timestamp": alert_time.isoformat(),
                "rule_name": pattern["rule"],
                "severity": severity,
                "source_ip": pattern["ip"],
                "destination_ip": f"192.168.1.{random.randint(1, 254)}",
                "user": pattern["user"],
                "host": pattern["host"],
                "process": pattern["process"],
                "description": f"{pattern['rule']} — {pattern['process']} on {pattern['host']} by {pattern['user']}",
                "analyst_decision": None,
                "analyst_notes": None,
                "analyst_id": None,
                "resolved_at": None,
                "time_to_resolve_seconds": 0,
                "mitre_technique": technique,
                "mitre_tactic": tactic,
            })

    # Suspicious alerts — external IPs, known bad processes (likely TPs)
    suspicious_rules = [r for r in CURATED_RULES if r["severity"] in ("critical", "high")]
    for _ in range(10):
        rule = random.choice(suspicious_rules)
        alert_time = base_time + timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        alerts.append({
            "alert_id": f"ALT-{len(alerts)+1:05d}",
            "timestamp": alert_time.isoformat(),
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "source_ip": f"203.0.113.{random.randint(1, 254)}",
            "destination_ip": f"192.168.1.{random.randint(1, 254)}",
            "user": random.choice(suspicious_users),
            "host": f"WORKSTATION-{random.randint(1, 50):02d}",
            "process": random.choice(["mimikatz.exe", "psexec.exe", "cobalt_strike.exe", "unknown.exe"]),
            "description": f"{rule['name']} — external source, suspicious process",
            "analyst_decision": None,
            "analyst_notes": None,
            "analyst_id": None,
            "resolved_at": None,
            "time_to_resolve_seconds": 0,
            "mitre_technique": rule.get("technique"),
            "mitre_tactic": rule.get("tactic"),
        })

    # Ambiguous internal alerts — mix of rules, legit and suspicious users
    all_rules = CURATED_RULES
    for _ in range(15):
        rule = random.choice(all_rules)
        alert_time = base_time + timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        alerts.append({
            "alert_id": f"ALT-{len(alerts)+1:05d}",
            "timestamp": alert_time.isoformat(),
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "source_ip": f"10.0.{random.randint(1, 20)}.{random.randint(1, 254)}",
            "destination_ip": f"192.168.1.{random.randint(1, 254)}",
            "user": random.choice(legit_users + suspicious_users),
            "host": f"HOST-{random.randint(1, 100):03d}",
            "process": random.choice(["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"]),
            "description": f"{rule['name']} — requires analyst review",
            "analyst_decision": None,
            "analyst_notes": None,
            "analyst_id": None,
            "resolved_at": None,
            "time_to_resolve_seconds": 0,
            "mitre_technique": rule.get("technique"),
            "mitre_tactic": rule.get("tactic"),
        })

    alerts.sort(key=lambda a: a["timestamp"])
    return alerts
