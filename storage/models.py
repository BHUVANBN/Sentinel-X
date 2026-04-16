"""
SENTINEL-X Database ORM Models — SQLAlchemy 2.0
Tables: alerts, response_actions, event_log, baselines
"""
from sqlalchemy import Column, String, Float, Integer, Text, DateTime, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime, timezone

Base = declarative_base()


class AlertModel(Base):
    """Confirmed alerts with full narrative and evidence."""
    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    rule_id = Column(String, nullable=False)
    rule_name = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # low | medium | high | critical
    confidence = Column(Float, nullable=False)
    source_ip = Column(String, nullable=True)
    target_host = Column(String, nullable=True)
    event_count = Column(Integer, default=0)
    time_window_seconds = Column(Integer, default=0)
    mitre_tech = Column(String, nullable=True)
    mitre_tactic = Column(String, nullable=True)
    correlated_rules = Column(Text, nullable=True)  # JSON array
    narrative = Column(Text, nullable=True)          # JSON from LLM
    evidence = Column(Text, nullable=True)           # JSON array of events
    status = Column(String, default="open")          # open | responded | closed

    # Relationships
    actions = relationship("ResponseActionModel", back_populates="alert", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "target_host": self.target_host,
            "event_count": self.event_count,
            "time_window_seconds": self.time_window_seconds,
            "mitre_tech": self.mitre_tech,
            "mitre_tactic": self.mitre_tactic,
            "correlated_rules": self.correlated_rules,
            "narrative": self.narrative,
            "evidence": self.evidence,
            "status": self.status,
        }


class ResponseActionModel(Base):
    """Proposed and executed response actions."""
    __tablename__ = "response_actions"

    id = Column(String, primary_key=True)
    alert_id = Column(String, ForeignKey("alerts.id"), nullable=False)
    action_type = Column(String, nullable=False)  # block_ip | kill_process | restrict_user | ...
    command = Column(Text, nullable=False)
    justification = Column(Text, nullable=True)
    status = Column(String, default="pending")    # pending | approved | skipped | executed | failed
    executed_at = Column(DateTime, nullable=True)
    result = Column(Text, nullable=True)

    # Relationships
    alert = relationship("AlertModel", back_populates="actions")

    def to_dict(self):
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "action_type": self.action_type,
            "command": self.command,
            "justification": self.justification,
            "status": self.status,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "result": self.result,
        }


class EventLogModel(Base):
    """Recent raw events — rolling 24h retention."""
    __tablename__ = "event_log"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    platform = Column(String, nullable=True)
    event_type = Column(String, nullable=True)
    category = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    dest_ip = Column(String, nullable=True)
    dest_port = Column(Integer, nullable=True)
    process_name = Column(String, nullable=True)
    user = Column(String, nullable=True)
    raw_payload = Column(Text, nullable=True)  # JSON

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "platform": self.platform,
            "event_type": self.event_type,
            "category": self.category,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "process_name": self.process_name,
            "user": self.user,
        }


class BaselineModel(Base):
    """Behavioral baselines for anomaly detection."""
    __tablename__ = "baselines"

    id = Column(String, primary_key=True)
    metric_name = Column(String, nullable=False)   # e.g. 'avg_login_rate', 'normal_outbound_bytes'
    value = Column(Float, nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    platform = Column(String, nullable=True)
