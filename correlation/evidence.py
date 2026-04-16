"""
SENTINEL-X Evidence Bundle — dataclasses for correlation evidence.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class EvidenceItem:
    """A single piece of evidence from a detection rule."""
    rule_id: str
    rule_name: str
    timestamp: datetime
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    event_count: int = 0
    details: dict = field(default_factory=dict)


@dataclass
class EvidenceBundle:
    """
    A collection of correlated evidence items that together
    form a higher-confidence alert.
    """
    correlation_id: str
    correlation_name: str
    items: list[EvidenceItem] = field(default_factory=list)
    confidence_boost: float = 0
    severity_override: Optional[str] = None
    mitre_chain: list[str] = field(default_factory=list)
    link_field: Optional[str] = None
    link_value: Optional[str] = None

    @property
    def total_events(self) -> int:
        return sum(item.event_count for item in self.items)

    @property
    def rule_ids(self) -> list[str]:
        return [item.rule_id for item in self.items]

    @property
    def summary(self) -> str:
        rules = ", ".join(f"{i.rule_name}" for i in self.items)
        return f"{self.correlation_name}: [{rules}] linked by {self.link_field}={self.link_value}"
