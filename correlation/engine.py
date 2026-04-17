"""
SENTINEL-X Correlation Engine
Combines evidence from multiple independent detection rules to produce
high-confidence, multi-signal alert bundles.
"""
import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from detection.engine import CandidateAlert
from correlation.evidence import EvidenceItem, EvidenceBundle

logger = logging.getLogger("sentinel.correlation")


# ─── Correlation Rule Definitions ───────────────────────

CORRELATION_RULES = [
    {
        'id': 'CORR-001',
        'name': 'Credential Access then Lateral Movement',
        'description': 'Brute force from an IP followed by internal pivot from same IP',
        'triggers': ['BF-001', 'LM-001'],
        'link_field': 'source_ip',
        'time_window_seconds': 300,
        'confidence_boost': 15,
        'severity_override': 'critical',
        'mitre_chain': ['T1110', 'T1021'],
    },
    {
        'id': 'CORR-002',
        'name': 'Password Spray then Lateral Movement',
        'description': 'Password spray attack followed by lateral pivot',
        'triggers': ['PS-001', 'LM-001'],
        'link_field': 'source_ip',
        'time_window_seconds': 300,
        'confidence_boost': 15,
        'severity_override': 'critical',
        'mitre_chain': ['T1110.003', 'T1021'],
    },
    {
        'id': 'CORR-003',
        'name': 'C2 Beacon with Data Exfiltration',
        'description': 'Periodic beacon followed by large data transfer to same destination',
        'triggers': ['C2-001', 'EX-001'],
        'link_field': 'dest_ip',
        'time_window_seconds': 600,
        'confidence_boost': 20,
        'severity_override': 'critical',
        'mitre_chain': ['T1071', 'T1041'],
    },
    {
        'id': 'CORR-004',
        'name': 'Privilege Escalation with Suspicious Process',
        'description': 'Non-root to root escalation followed by suspicious process execution',
        'triggers': ['PE-001', 'SP-001'],
        'link_field': 'pid',
        'time_window_seconds': 120,
        'confidence_boost': 20,
        'severity_override': 'critical',
        'mitre_chain': ['T1548', 'T1059'],
    },
    {
        'id': 'CORR-005',
        'name': 'Port Scan then Lateral Movement',
        'description': 'Network reconnaissance followed by lateral movement attempt',
        'triggers': ['PS-002', 'LM-001'],
        'link_field': 'source_ip',
        'time_window_seconds': 600,
        'confidence_boost': 10,
        'severity_override': 'high',
        'mitre_chain': ['T1046', 'T1021'],
    },
    {
        'id': 'CORR-006',
        'name': 'Brute Force then Privilege Escalation',
        'description': 'Credential attack followed by privilege escalation',
        'triggers': ['BF-001', 'PE-001'],
        'link_field': 'source_ip',
        'time_window_seconds': 600,
        'confidence_boost': 20,
        'severity_override': 'critical',
        'mitre_chain': ['T1110', 'T1548'],
    },
    {
        'id': 'CORR-007',
        'name': 'Full Attack Chain — Credential to Exfiltration',
        'description': 'Brute force → lateral movement → exfiltration',
        'triggers': ['BF-001', 'LM-001', 'EX-001'],
        'link_field': 'source_ip',
        'time_window_seconds': 900,
        'confidence_boost': 25,
        'severity_override': 'critical',
        'mitre_chain': ['T1110', 'T1021', 'T1041'],
    },
    {
        'id': 'CORR-008',
        'name': 'Full Attack Lifecycle (v3.0)',
        'description': 'Reconnaissance → Brute Force → Web Probe → C2 establishment',
        'triggers': ['RECON-001', 'BF-001', 'WEB-002', 'C2-001'],
        'link_field': 'source_ip',
        'time_window_seconds': 1800,
        'confidence_boost': 30,
        'severity_override': 'critical',
        'mitre_chain': ['T1046', 'T1110', 'T1018', 'T1071'],
    },
]


@dataclass
class CorrelatedAlert:
    """Alert enriched with correlation data."""
    alert_id: str
    timestamp: datetime
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    source_ip: Optional[str]
    dest_ip: Optional[str]
    target_host: Optional[str]
    event_count: int
    time_window_seconds: int
    mitre_technique: str
    mitre_tactic: str
    correlated_rules: list[str]
    evidence_summary: list[dict]
    is_correlated: bool = False
    correlation_id: Optional[str] = None
    correlation_name: Optional[str] = None
    mitre_chain: list[str] = field(default_factory=list)
    platform: str = "linux"  # Default to linux

    @classmethod
    def from_single(cls, candidate: CandidateAlert) -> 'CorrelatedAlert':
        """Create a CorrelatedAlert from a single (uncorrelated) CandidateAlert."""
        evidence_summary = []
        for ts, evt in candidate.evidence[:10]:  # Keep last 10 events
            evidence_summary.append({
                "timestamp": evt.timestamp.isoformat(),
                "event_type": evt.event_type,
                "source_ip": evt.source_ip,
                "dest_ip": evt.dest_ip,
                "dest_port": evt.dest_port,
                "process_name": evt.process_name,
                "user": evt.user,
                "pid": evt.pid,
            })

        return cls(
            alert_id=str(uuid.uuid4()),
            timestamp=candidate.timestamp,
            rule_id=candidate.rule.id,
            rule_name=candidate.rule.name,
            severity=candidate.rule.severity,
            confidence=candidate.rule.confidence_base / 100.0,
            source_ip=candidate.source_ip,
            dest_ip=candidate.dest_ip,
            target_host=None,
            event_count=candidate.event_count,
            time_window_seconds=candidate.time_window_seconds,
            mitre_technique=candidate.rule.mitre_technique,
            mitre_tactic=candidate.rule.mitre_tactic,
            correlated_rules=[candidate.rule.id],
            evidence_summary=evidence_summary,
            is_correlated=False,
            mitre_chain=[candidate.rule.mitre_technique],
            platform=candidate.evidence[0][1].platform if candidate.evidence else "linux",
        )


class CorrelationEngine:
    """
    Multi-signal correlation engine.

    Receives CandidateAlert objects from the Detection Engine and checks
    whether they can be combined with other recent candidates to form
    a higher-confidence, correlated alert.

    If correlation matches, produces a CorrelatedAlert with boosted confidence
    and severity override. Otherwise, passes through as a single-rule alert.
    """

    def __init__(self):
        # Pending candidates: rule_id -> [CandidateAlert]
        self._pending: dict[str, list[CandidateAlert]] = defaultdict(list)
        # Retention window for pending candidates (seconds)
        self._max_retention = 900  # 15 minutes
        self._correlation_count = 0

        logger.info(f"Correlation engine initialized with {len(CORRELATION_RULES)} correlation rules")

    def feed(self, candidate: CandidateAlert) -> CorrelatedAlert:
        """
        Feed a CandidateAlert into the correlation engine.

        Returns a CorrelatedAlert — either correlated (multi-signal) or
        passed through (single detection rule).
        """
        # Store candidate
        self._pending[candidate.rule.id].append(candidate)

        # Prune old candidates
        self._prune()

        # Check all correlation rules
        for corr_rule in CORRELATION_RULES:
            result = self._check_correlation(corr_rule, candidate)
            if result:
                self._correlation_count += 1
                logger.info(
                    f"Correlation matched: {corr_rule['id']} — {corr_rule['name']} "
                    f"(rules: {corr_rule['triggers']})"
                )
                return result

        # No correlation found — pass through as single alert
        return CorrelatedAlert.from_single(candidate)

    def _check_correlation(self, corr_rule: dict,
                           latest: CandidateAlert) -> Optional[CorrelatedAlert]:
        """Check if a correlation rule is satisfied."""
        required_rules = set(corr_rule['triggers'])

        # Quick check: is the latest candidate's rule one of the triggers?
        if latest.rule.id not in required_rules:
            return None

        # Check all required rules have pending candidates
        present_rules = set(
            r for r in required_rules if self._pending.get(r)
        )
        if not required_rules.issubset(present_rules):
            return None

        # Verify link field matches across all trigger rules
        link_field = corr_rule['link_field']
        time_window = corr_rule['time_window_seconds']
        now = datetime.now(timezone.utc).timestamp()

        # Gather link values per rule
        link_values_per_rule = []
        matched_candidates = {}

        for rule_id in required_rules:
            candidates = self._pending.get(rule_id, [])
            values = set()
            for cand in candidates:
                # Check time window
                if now - cand.timestamp.timestamp() > time_window:
                    continue
                val = self._get_link_value(cand, link_field)
                if val:
                    values.add(val)
                    matched_candidates.setdefault(rule_id, []).append(cand)
            link_values_per_rule.append(values)

        if not link_values_per_rule:
            return None

        # Find intersection of link values
        common_values = set.intersection(*link_values_per_rule)
        if not common_values:
            return None

        # Build correlated alert
        link_value = next(iter(common_values))
        return self._build_correlated_alert(corr_rule, matched_candidates, link_value)

    def _build_correlated_alert(self, corr_rule: dict,
                                 matched_candidates: dict[str, list],
                                 link_value: str) -> CorrelatedAlert:
        """Build a CorrelatedAlert from matched correlation rule."""
        # Collect all evidence
        all_evidence = []
        total_events = 0
        source_ips = set()
        dest_ips = set()
        rule_ids = []

        for rule_id, candidates in matched_candidates.items():
            best = candidates[-1]  # Most recent
            rule_ids.append(rule_id)
            total_events += best.event_count
            if best.source_ip:
                source_ips.add(best.source_ip)
            if best.dest_ip:
                dest_ips.add(best.dest_ip)

            for ts, evt in best.evidence[:5]:
                all_evidence.append({
                    "rule_id": rule_id,
                    "timestamp": evt.timestamp.isoformat(),
                    "event_type": evt.event_type,
                    "source_ip": evt.source_ip,
                    "dest_ip": evt.dest_ip,
                    "process_name": evt.process_name,
                    "user": evt.user,
                    "platform": getattr(evt, 'platform', 'linux'),
                })

        # Calculate boosted confidence
        base_confidence = max(
            c.rule.confidence_base for cs in matched_candidates.values() for c in cs
        )
        
        # intelliSOC Style: Multi-layer diversity boost
        unique_categories = set()
        for candidates in matched_candidates.values():
            for c in candidates:
                for _, evt in c.evidence:
                    if hasattr(evt, 'category'):
                        unique_categories.add(evt.category)
        
        layer_boost = max(0, (len(unique_categories) - 1) * 5)  # 5% per extra layer
        boosted = min(100, base_confidence + corr_rule['confidence_boost'] + layer_boost)

        return CorrelatedAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            rule_id=corr_rule['id'],
            rule_name=corr_rule['name'],
            severity=corr_rule.get('severity_override', 'critical'),
            confidence=boosted / 100.0,
            source_ip=next(iter(source_ips), None),
            dest_ip=next(iter(dest_ips), None),
            target_host=None,
            event_count=total_events,
            time_window_seconds=corr_rule['time_window_seconds'],
            mitre_technique=corr_rule['mitre_chain'][0],
            mitre_tactic="Multi-Stage Attack",
            correlated_rules=rule_ids,
            evidence_summary=all_evidence,
            is_correlated=True,
            correlation_id=corr_rule['id'],
            correlation_name=corr_rule['name'],
            mitre_chain=corr_rule['mitre_chain'],
            platform=all_evidence[0].get('platform', 'linux') if all_evidence else "linux",
        )

    def _get_link_value(self, candidate: CandidateAlert, field: str) -> Optional[str]:
        """Get the link field value from a candidate alert."""
        # Check direct attributes
        val = getattr(candidate, field, None)
        if val:
            return str(val)

        # Check evidence events
        for _, evt in candidate.evidence:
            val = getattr(evt, field, None)
            if val:
                return str(val)

        return None

    def _prune(self):
        """Remove expired candidates."""
        now = datetime.now(timezone.utc).timestamp()
        for rule_id in list(self._pending.keys()):
            self._pending[rule_id] = [
                c for c in self._pending[rule_id]
                if now - c.timestamp.timestamp() <= self._max_retention
            ]
            if not self._pending[rule_id]:
                del self._pending[rule_id]

    def get_stats(self) -> dict:
        """Get correlation engine statistics."""
        return {
            "pending_candidates": sum(len(v) for v in self._pending.values()),
            "pending_by_rule": {k: len(v) for k, v in self._pending.items()},
            "total_correlations": self._correlation_count,
            "correlation_rules": len(CORRELATION_RULES),
        }
