"""
False Positive Detection Engine
Analyzes analyst decisions to identify FP patterns and suggest tuning rules.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter
import re


@dataclass
class Alert:
    """Single SOC alert with analyst decision."""
    alert_id: str
    timestamp: str
    rule_name: str
    severity: str  # critical / high / medium / low
    source_ip: str
    destination_ip: str
    user: str
    host: str
    process: str
    description: str
    analyst_decision: Optional[str] = None  # true_positive / false_positive / pending
    analyst_notes: Optional[str] = None
    analyst_id: Optional[str] = None
    resolved_at: Optional[str] = None
    time_to_resolve_seconds: Optional[int] = 0
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None


@dataclass
class TuningRule:
    """Suggested tuning rule based on FP patterns."""
    rule_id: str
    name: str
    description: str
    pattern: Dict[str, Any]  # field → value(s) to match
    fp_count: int
    confidence: float  # 0.0 - 1.0
    estimated_fp_reduction: int  # per week
    estimated_time_saved_minutes: int  # per week
    suggested_action: str  # suppress / lower_severity / whitelist
    created_at: str
    status: str = "pending"  # pending / approved / rejected / applied


class FPDetectionEngine:
    """Detects FP patterns and generates tuning rule suggestions."""

    # Minimum FPs required to suggest a rule
    MIN_FP_THRESHOLD = 3
    # Average time per alert (minutes) — for time-saved calculation
    AVG_TIME_PER_ALERT = 8

    def __init__(self):
        self.alerts: List[Alert] = []
        self.tuning_rules: List[TuningRule] = []

    def add_alerts(self, alerts: List[Dict[str, Any]]):
        """Bulk add alerts from input data."""
        for alert_data in alerts:
            alert = Alert(**{k: v for k, v in alert_data.items() if k in Alert.__annotations__})
            self.alerts.append(alert)

    def update_decision(self, alert_id: str, decision: str, notes: str = "", analyst_id: str = "analyst_1"):
        """Update analyst decision on an alert."""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.analyst_decision = decision
                alert.analyst_notes = notes
                alert.analyst_id = analyst_id
                alert.resolved_at = datetime.now().isoformat()
                return True
        return False

    def get_fp_alerts(self) -> List[Alert]:
        """Return all alerts marked as false positives."""
        return [a for a in self.alerts if a.analyst_decision == "false_positive"]

    def detect_patterns(self) -> List[TuningRule]:
        """
        Analyze FPs to detect common patterns.
        Groups by combinations of: rule_name + source_ip / user / process / host
        """
        fps = self.get_fp_alerts()
        if len(fps) < self.MIN_FP_THRESHOLD:
            return []

        patterns: Dict[str, List[Alert]] = defaultdict(list)

        # Pattern 1: Same rule + same source IP
        for fp in fps:
            key = f"rule_ip::{fp.rule_name}::{fp.source_ip}"
            patterns[key].append(fp)

        # Pattern 2: Same rule + same user
        for fp in fps:
            key = f"rule_user::{fp.rule_name}::{fp.user}"
            patterns[key].append(fp)

        # Pattern 3: Same rule + same process
        for fp in fps:
            key = f"rule_proc::{fp.rule_name}::{fp.process}"
            patterns[key].append(fp)

        # Pattern 4: Same rule + same host
        for fp in fps:
            key = f"rule_host::{fp.rule_name}::{fp.host}"
            patterns[key].append(fp)

        # Generate suggestions for patterns with enough FPs
        suggestions: List[TuningRule] = []
        seen_rules = set()

        for pattern_key, matching_fps in patterns.items():
            if len(matching_fps) < self.MIN_FP_THRESHOLD:
                continue

            pattern_type, rule_name, value = pattern_key.split("::", 2)
            rule_signature = f"{pattern_type}_{rule_name}_{value}"
            if rule_signature in seen_rules:
                continue
            seen_rules.add(rule_signature)

            field_map = {
                "rule_ip": ("source_ip", "Source IP"),
                "rule_user": ("user", "User"),
                "rule_proc": ("process", "Process"),
                "rule_host": ("host", "Host"),
            }
            field_name, field_label = field_map[pattern_type]

            fp_count = len(matching_fps)
            confidence = min(0.95, 0.5 + (fp_count * 0.05))
            est_weekly_fps = fp_count * 2  # rough projection
            est_time_saved = est_weekly_fps * self.AVG_TIME_PER_ALERT

            rule = TuningRule(
                rule_id=f"TUN-{len(suggestions)+1:04d}",
                name=f"Suppress: {rule_name} from {field_label}={value}",
                description=(
                    f"Detected {fp_count} false positives for rule '{rule_name}' "
                    f"with {field_label.lower()} '{value}'. "
                    f"Recommend suppressing or whitelisting this combination."
                ),
                pattern={
                    "rule_name": rule_name,
                    field_name: value,
                },
                fp_count=fp_count,
                confidence=round(confidence, 2),
                estimated_fp_reduction=est_weekly_fps,
                estimated_time_saved_minutes=est_time_saved,
                suggested_action="suppress" if fp_count >= 5 else "lower_severity",
                created_at=datetime.now().isoformat(),
            )
            suggestions.append(rule)

        suggestions.sort(key=lambda r: (r.fp_count, r.confidence), reverse=True)
        self.tuning_rules = suggestions
        return suggestions

    def apply_rule(self, rule_id: str) -> bool:
        """Mark rule as applied."""
        for rule in self.tuning_rules:
            if rule.rule_id == rule_id:
                rule.status = "applied"
                return True
        return False

    def reject_rule(self, rule_id: str) -> bool:
        """Mark rule as rejected."""
        for rule in self.tuning_rules:
            if rule.rule_id == rule_id:
                rule.status = "rejected"
                return True
        return False

    def get_metrics(self) -> Dict[str, Any]:
        """Calculate dashboard metrics."""
        total = len(self.alerts)
        fps = self.get_fp_alerts()
        tps = [a for a in self.alerts if a.analyst_decision == "true_positive"]
        pending = [a for a in self.alerts if a.analyst_decision in (None, "pending")]
        applied_rules = [r for r in self.tuning_rules if r.status == "applied"]

        fp_rate = (len(fps) / total * 100) if total > 0 else 0
        tp_rate = (len(tps) / total * 100) if total > 0 else 0

        # FPs by rule
        fp_by_rule = Counter(a.rule_name for a in fps)
        top_fp_rules = [
            {"rule": rule, "count": count, "percentage": round(count / len(fps) * 100, 1)}
            for rule, count in fp_by_rule.most_common(5)
        ] if fps else []

        # Estimated time saved from applied rules
        time_saved_weekly = sum(r.estimated_time_saved_minutes for r in applied_rules)
        fp_reduction_weekly = sum(r.estimated_fp_reduction for r in applied_rules)

        return {
            "total_alerts": total,
            "false_positives": len(fps),
            "true_positives": len(tps),
            "pending": len(pending),
            "fp_rate": round(fp_rate, 1),
            "tp_rate": round(tp_rate, 1),
            "suggested_rules": len([r for r in self.tuning_rules if r.status == "pending"]),
            "applied_rules": len(applied_rules),
            "rejected_rules": len([r for r in self.tuning_rules if r.status == "rejected"]),
            "time_saved_weekly_minutes": time_saved_weekly,
            "time_saved_weekly_hours": round(time_saved_weekly / 60, 1),
            "fp_reduction_weekly": fp_reduction_weekly,
            "top_fp_rules": top_fp_rules,
        }

    def get_severity_distribution(self) -> Dict[str, int]:
        """Alerts grouped by severity."""
        return dict(Counter(a.severity for a in self.alerts))

    def get_decision_distribution(self) -> Dict[str, int]:
        """Alerts grouped by analyst decision."""
        return {
            "true_positive": len([a for a in self.alerts if a.analyst_decision == "true_positive"]),
            "false_positive": len([a for a in self.alerts if a.analyst_decision == "false_positive"]),
            "pending": len([a for a in self.alerts if a.analyst_decision in (None, "pending")]),
        }
