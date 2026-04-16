"""
SENTINEL-X Detection Engine
Evaluates normalized events against detection rules using sliding-window aggregation.
Produces CandidateAlert objects for the Correlation Engine.
"""
import ipaddress
import logging
import os
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from normalizer.schema import NormalizedEvent
from detection.rule_loader import DetectionRule

logger = logging.getLogger("sentinel.detection")


@dataclass
class CandidateAlert:
    """Alert candidate produced by the Detection Engine."""
    rule: DetectionRule
    evidence: list  # List of (timestamp_float, NormalizedEvent) tuples
    group_key: tuple = ()
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    target_host: Optional[str] = None
    event_count: int = 0
    time_window_seconds: int = 0
    unique_values: set = field(default_factory=set)

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def confidence(self) -> float:
        return self.rule.confidence_base

    @property
    def rule_id(self) -> str:
        return self.rule.id


# ─── Internal IP detection ─────────────────────────────

INTERNAL_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fe80::/10'),
]


def is_internal_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to an internal/private network."""
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


def is_external_ip(ip_str: str) -> bool:
    """Check if an IP address is external/public."""
    if not ip_str:
        return False
    return not is_internal_ip(ip_str)


class DetectionEngine:
    """
    Detection engine that evaluates normalized events against YAML detection rules.
    Uses sliding-window aggregation with support for:
    - Count thresholds
    - Unique value counting (password spray, port scan)
    - Sum aggregation (data exfiltration)
    - Periodicity detection (C2 beacon)
    """

    def __init__(self, rules: list[DetectionRule]):
        self.rules = [r for r in rules if r.enabled]
        # Sliding windows: rule_id -> group_key -> [(timestamp_float, NormalizedEvent)]
        self._windows: dict[str, dict[tuple, list]] = defaultdict(lambda: defaultdict(list))
        # Track which group_keys have already fired, to avoid duplicate alerts
        self._fired: dict[str, dict[tuple, float]] = defaultdict(dict)
        # Minimum cooldown before re-alerting (seconds)
        demo_mode = os.getenv('SENTINEL_DEMO_MODE', '').lower() in ('1', 'true', 'yes')
        self._cooldown = 30 if demo_mode else 300
        if demo_mode:
            logger.info('DEMO MODE: alert cooldown set to 30s')

        logger.info(f"Detection engine initialized with {len(self.rules)} active rules")

    def evaluate(self, event: NormalizedEvent) -> list[CandidateAlert]:
        """
        Evaluate a single normalized event against all active rules.
        Returns a list of CandidateAlert objects for matching rules.
        """
        alerts = []
        now = datetime.now(timezone.utc).timestamp()

        for rule in self.rules:
            # Step 1: Check basic match criteria
            if not self._matches(event, rule):
                continue

            # Step 2: Check additional conditions
            if not self._check_conditions(event, rule):
                continue

            # Step 3: Build group key
            group_key = tuple(
                getattr(event, f, None) for f in rule.aggregate.group_by
            )

            # Step 4: Add to sliding window
            win = self._windows[rule.id][group_key]
            win.append((now, event))

            # Step 5: Prune expired events
            window_seconds = rule.aggregate.time_window_seconds
            win[:] = [(t, e) for t, e in win if now - t <= window_seconds]

            # Step 6: Check if threshold is met
            alert = self._check_threshold(rule, group_key, win, now)
            if alert:
                # Check cooldown
                last_fired = self._fired.get(rule.id, {}).get(group_key, 0)
                if now - last_fired > self._cooldown:
                    self._fired[rule.id][group_key] = now
                    alerts.append(alert)
                    logger.info(
                        f"Rule {rule.id} triggered: {rule.name} "
                        f"(group={group_key}, events={len(win)})"
                    )

        return alerts

    def _matches(self, event: NormalizedEvent, rule: DetectionRule) -> bool:
        """Check if event matches the basic rule match criteria."""
        match = rule.match

        if match.event_type and event.event_type != match.event_type:
            return False
        if match.category and event.category != match.category:
            return False
        if match.outcome and event.outcome != match.outcome:
            return False

        return True

    def _check_conditions(self, event: NormalizedEvent, rule: DetectionRule) -> bool:
        """Check additional conditions on the event."""
        for cond in rule.conditions:
            value = getattr(event, cond.field, None)

            if cond.operator == 'eq':
                if value != cond.value:
                    return False
            elif cond.operator == 'neq':
                if value == cond.value:
                    return False
            elif cond.operator == 'in':
                if value not in cond.values:
                    return False
            elif cond.operator == 'gte':
                if value is None or value < cond.value:
                    return False
            elif cond.operator == 'lte':
                if value is None or value > cond.value:
                    return False
            elif cond.operator == 'is_internal':
                if not is_internal_ip(str(value) if value else ''):
                    return False
            elif cond.operator == 'is_external':
                if not is_external_ip(str(value) if value else ''):
                    return False
            elif cond.operator == 'regex':
                if value is None or not re.search(str(cond.value), str(value), re.IGNORECASE):
                    return False

        return True

    def _check_threshold(self, rule: DetectionRule, group_key: tuple,
                         window: list, now: float) -> Optional[CandidateAlert]:
        """Check if the aggregation threshold is met for a rule."""
        agg = rule.aggregate

        # ── Count threshold ──────────────────────
        if agg.unique_field:
            # Unique value counting (password spray, port scan)
            unique_values = set()
            for _, evt in window:
                val = getattr(evt, agg.unique_field, None)
                if val is not None:
                    unique_values.add(val)

            if len(unique_values) >= (agg.unique_threshold or agg.count_threshold):
                return self._build_alert(rule, group_key, window, unique_values)

        elif agg.sum_field:
            # Sum aggregation (data exfiltration)
            total = sum(
                getattr(evt, agg.sum_field, 0) or 0
                for _, evt in window
            )
            if total >= (agg.sum_threshold or 0):
                return self._build_alert(rule, group_key, window)

        elif agg.periodicity_check:
            # Periodicity detection (C2 beacon)
            if len(window) >= agg.count_threshold:
                if self._check_periodicity(window, agg.interval_variance_percent):
                    return self._build_alert(rule, group_key, window)

        else:
            # Simple count threshold
            if len(window) >= agg.count_threshold:
                return self._build_alert(rule, group_key, window)

        return None

    def _check_periodicity(self, window: list, variance_pct: int) -> bool:
        """Check if connection timestamps show periodic behavior."""
        if len(window) < 3:
            return False

        timestamps = sorted(t for t, _ in window)
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if not intervals:
            return False

        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            return False

        # Check if variance is within threshold
        try:
            stdev = statistics.stdev(intervals)
            coefficient_of_variation = (stdev / mean_interval) * 100
            return coefficient_of_variation <= variance_pct
        except statistics.StatisticsError:
            return False

    def _build_alert(self, rule: DetectionRule, group_key: tuple,
                     window: list, unique_values: set = None) -> CandidateAlert:
        """Build a CandidateAlert from a rule match."""
        events = [e for _, e in window]

        # Extract common fields from evidence
        source_ips = {e.source_ip for e in events if e.source_ip}
        dest_ips = {e.dest_ip for e in events if e.dest_ip}

        return CandidateAlert(
            rule=rule,
            evidence=window.copy(),
            group_key=group_key,
            timestamp=datetime.now(timezone.utc),
            source_ip=next(iter(source_ips), None),
            dest_ip=next(iter(dest_ips), None),
            event_count=len(window),
            time_window_seconds=rule.aggregate.time_window_seconds,
            unique_values=unique_values or set(),
        )

    def get_stats(self) -> dict:
        """Get detection engine statistics."""
        total_windows = sum(
            len(groups) for groups in self._windows.values()
        )
        total_events = sum(
            len(window)
            for groups in self._windows.values()
            for window in groups.values()
        )
        return {
            "active_rules": len(self.rules),
            "active_windows": total_windows,
            "events_in_windows": total_events,
            "rules": [
                {"id": r.id, "name": r.name, "severity": r.severity}
                for r in self.rules
            ],
        }
