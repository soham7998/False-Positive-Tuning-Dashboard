"""
Sample SOC alerts with realistic FP patterns for demo purposes.
"""

from datetime import datetime, timedelta
import random
import json


def generate_sample_alerts(count: int = 50) -> list:
    """Generate realistic SOC alerts with embedded FP patterns."""
    
    base_time = datetime.now() - timedelta(days=7)
    
    rules = [
        ("Suspicious PowerShell Execution", "high"),
        ("Multiple Failed Login Attempts", "medium"),
        ("Unusual Outbound Traffic", "medium"),
        ("Process Injection Detected", "high"),
        ("Brute Force Attempt", "high"),
        ("DNS Tunneling Suspected", "medium"),
        ("Privilege Escalation Attempt", "critical"),
        ("Unauthorized Software Install", "low"),
        ("Anomalous User Behavior", "medium"),
        ("Suspicious Registry Modification", "high"),
    ]
    
    # FP-prone patterns (these will repeat to create patterns)
    fp_patterns = [
        # IT admin running scripts (FP)
        {"rule": "Suspicious PowerShell Execution", "ip": "10.0.1.50", "user": "admin_it_01", "process": "powershell.exe", "host": "IT-WORKSTATION-05"},
        # Backup service (FP)
        {"rule": "Unusual Outbound Traffic", "ip": "10.0.5.20", "user": "svc_backup", "process": "backup_agent.exe", "host": "BACKUP-SRV-01"},
        # Dev environment (FP)
        {"rule": "Process Injection Detected", "ip": "10.0.10.100", "user": "dev_team", "process": "debugger.exe", "host": "DEV-MACHINE-12"},
        # Scheduled monitoring (FP)
        {"rule": "Multiple Failed Login Attempts", "ip": "10.0.2.10", "user": "svc_monitor", "process": "monitor_agent.exe", "host": "MON-SRV-01"},
    ]
    
    users_legit = ["john.doe", "alice.smith", "bob.johnson", "sarah.davis", "mike.wilson"]
    users_suspicious = ["unknown_user", "guest", "anonymous"]
    
    alerts = []
    
    # Inject FP patterns (each pattern appears 4-6 times)
    for pattern in fp_patterns:
        repetitions = random.randint(4, 6)
        rule_severity = next((s for r, s in rules if r == pattern["rule"]), "medium")
        
        for i in range(repetitions):
            alert_time = base_time + timedelta(
                days=random.randint(0, 6),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )

            alerts.append({
                "alert_id": f"ALT-{len(alerts)+1:05d}",
                "timestamp": alert_time.isoformat(),
                "rule_name": pattern["rule"],
                "severity": rule_severity,
                "source_ip": pattern["ip"],
                "destination_ip": f"192.168.1.{random.randint(1, 254)}",
                "user": pattern["user"],
                "host": pattern["host"],
                "process": pattern["process"],
                "description": f"Rule '{pattern['rule']}' triggered by {pattern['process']} on {pattern['host']}",
                "analyst_decision": None,
                "analyst_notes": None,
                "analyst_id": None,
                "resolved_at": None,
                "time_to_resolve_seconds": 0,
            })

    # Add suspicious alerts (likely TPs — external IPs, known bad processes)
    for _ in range(8):
        rule, severity = random.choice(rules)
        alert_time = base_time + timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )

        alerts.append({
            "alert_id": f"ALT-{len(alerts)+1:05d}",
            "timestamp": alert_time.isoformat(),
            "rule_name": rule,
            "severity": severity,
            "source_ip": f"203.0.113.{random.randint(1, 254)}",
            "destination_ip": f"192.168.1.{random.randint(1, 254)}",
            "user": random.choice(users_suspicious),
            "host": f"WORKSTATION-{random.randint(1, 50):02d}",
            "process": random.choice(["malware.exe", "unknown.exe", "mimikatz.exe"]),
            "description": f"Rule '{rule}' triggered from external IP by {random.choice(users_suspicious)}",
            "analyst_decision": None,
            "analyst_notes": None,
            "analyst_id": None,
            "resolved_at": None,
            "time_to_resolve_seconds": 0,
        })

    # Add noise — internal alerts with ambiguous context
    for _ in range(15):
        rule, severity = random.choice(rules)
        alert_time = base_time + timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )

        alerts.append({
            "alert_id": f"ALT-{len(alerts)+1:05d}",
            "timestamp": alert_time.isoformat(),
            "rule_name": rule,
            "severity": severity,
            "source_ip": f"10.0.{random.randint(1, 20)}.{random.randint(1, 254)}",
            "destination_ip": f"192.168.1.{random.randint(1, 254)}",
            "user": random.choice(users_legit + users_suspicious),
            "host": f"HOST-{random.randint(1, 100):03d}",
            "process": random.choice(["powershell.exe", "cmd.exe", "explorer.exe", "chrome.exe"]),
            "description": f"Rule '{rule}' triggered — requires analyst review",
            "analyst_decision": None,
            "analyst_notes": None,
            "analyst_id": None,
            "resolved_at": None,
            "time_to_resolve_seconds": 0,
        })
    
    # Sort by timestamp
    alerts.sort(key=lambda a: a["timestamp"])
    
    return alerts


if __name__ == "__main__":
    sample = generate_sample_alerts()
    print(f"Generated {len(sample)} alerts")
    with open("data/sample_alerts.json", "w") as f:
        json.dump(sample, f, indent=2)
    print("Saved to data/sample_alerts.json")
