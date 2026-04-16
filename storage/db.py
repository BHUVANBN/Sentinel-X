"""
SENTINEL-X Database Manager — SQLAlchemy async/sync database operations.
Supports SQLite (dev) and PostgreSQL (prod).
"""
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

from storage.models import Base, AlertModel, ResponseActionModel, EventLogModel

logger = logging.getLogger("sentinel.storage")


class Database:
    """Database manager for SENTINEL-X."""

    def __init__(self, db_url: str = "sqlite:///data/sentinel.db"):
        self.db_url = db_url
        self.engine = create_engine(db_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)
        logger.info(f"Database initialized: {db_url}")

    def init_db(self):
        """Create all tables."""
        os.makedirs("data", exist_ok=True)
        Base.metadata.create_all(self.engine)
        logger.info("Database tables created successfully")

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    # ─── Alert Operations ───────────────────────────

    def save_alert(self, alert_data: dict) -> AlertModel:
        """Save a confirmed alert to the database."""
        with self.get_session() as session:
            alert = AlertModel(
                id=alert_data["alert_id"],
                timestamp=alert_data.get("timestamp", datetime.now(timezone.utc)),
                rule_id=alert_data["rule_id"],
                rule_name=alert_data["rule_name"],
                severity=alert_data["severity"],
                confidence=alert_data["confidence"],
                source_ip=alert_data.get("source_ip"),
                target_host=alert_data.get("target_host"),
                event_count=alert_data.get("event_count", 0),
                time_window_seconds=alert_data.get("time_window_seconds", 0),
                mitre_tech=alert_data.get("mitre_technique"),
                mitre_tactic=alert_data.get("mitre_tactic"),
                correlated_rules=json.dumps(alert_data.get("correlated_rules", [])),
                narrative=json.dumps(alert_data.get("narrative", {})),
                evidence=json.dumps(alert_data.get("evidence_summary", [])),
                status="open",
            )
            session.add(alert)
            session.commit()
            session.refresh(alert)
            logger.info(f"Alert saved: {alert.id} [{alert.severity}] {alert.rule_name}")
            return alert

    def get_alerts(self, limit: int = 50, offset: int = 0,
                   severity: Optional[str] = None, status: Optional[str] = None) -> list[dict]:
        """Get paginated alerts with optional filtering."""
        with self.get_session() as session:
            query = session.query(AlertModel).order_by(AlertModel.timestamp.desc())
            if severity:
                query = query.filter(AlertModel.severity == severity)
            if status:
                query = query.filter(AlertModel.status == status)
            alerts = query.offset(offset).limit(limit).all()
            return [a.to_dict() for a in alerts]

    def get_alert_by_id(self, alert_id: str) -> Optional[dict]:
        """Get a single alert with full detail."""
        with self.get_session() as session:
            alert = session.query(AlertModel).filter(AlertModel.id == alert_id).first()
            if alert:
                result = alert.to_dict()
                result["actions"] = [a.to_dict() for a in alert.actions]
                return result
            return None

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        """Update alert status (open | responded | closed)."""
        with self.get_session() as session:
            alert = session.query(AlertModel).filter(AlertModel.id == alert_id).first()
            if alert:
                alert.status = status
                session.commit()
                return True
            return False

    def get_alert_count(self, severity: Optional[str] = None) -> int:
        """Get count of alerts, optionally filtered by severity."""
        with self.get_session() as session:
            query = session.query(AlertModel)
            if severity:
                query = query.filter(AlertModel.severity == severity)
            return query.count()

    def get_alert_stats(self) -> dict:
        """Get alert statistics by severity and status."""
        with self.get_session() as session:
            total = session.query(AlertModel).count()
            by_severity = {}
            for sev in ["critical", "high", "medium", "low"]:
                by_severity[sev] = session.query(AlertModel).filter(
                    AlertModel.severity == sev
                ).count()
            by_status = {}
            for st in ["open", "responded", "closed"]:
                by_status[st] = session.query(AlertModel).filter(
                    AlertModel.status == st
                ).count()
            return {
                "total": total,
                "by_severity": by_severity,
                "by_status": by_status,
            }

    # ─── Response Action Operations ─────────────────

    def save_action(self, action_data: dict) -> ResponseActionModel:
        """Save a proposed response action."""
        with self.get_session() as session:
            action = ResponseActionModel(
                id=action_data["action_id"],
                alert_id=action_data["alert_id"],
                action_type=action_data["action_type"],
                command=action_data["command"],
                justification=action_data.get("justification", ""),
                status="pending",
            )
            session.add(action)
            session.commit()
            session.refresh(action)
            return action

    def update_action_status(self, action_id: str, status: str,
                             result: Optional[str] = None) -> bool:
        """Update action status after user decision or execution."""
        with self.get_session() as session:
            action = session.query(ResponseActionModel).filter(
                ResponseActionModel.id == action_id
            ).first()
            if action:
                action.status = status
                if status in ("executed", "failed"):
                    action.executed_at = datetime.now(timezone.utc)
                if result:
                    action.result = result
                session.commit()
                return True
            return False

    def get_pending_actions(self) -> list[dict]:
        """Get all pending response actions."""
        with self.get_session() as session:
            actions = session.query(ResponseActionModel).filter(
                ResponseActionModel.status == "pending"
            ).all()
            return [a.to_dict() for a in actions]

    def get_actions_for_alert(self, alert_id: str) -> list[dict]:
        """Get all actions for a specific alert."""
        with self.get_session() as session:
            actions = session.query(ResponseActionModel).filter(
                ResponseActionModel.alert_id == alert_id
            ).all()
            return [a.to_dict() for a in actions]

    # ─── Event Log Operations ───────────────────────

    def log_event(self, event_data: dict):
        """Log a normalized event for forensic review."""
        with self.get_session() as session:
            event = EventLogModel(
                id=event_data["event_id"],
                timestamp=event_data.get("timestamp", datetime.now(timezone.utc)),
                platform=event_data.get("platform"),
                event_type=event_data.get("event_type"),
                category=event_data.get("category"),
                source_ip=event_data.get("source_ip"),
                dest_ip=event_data.get("dest_ip"),
                dest_port=event_data.get("dest_port"),
                process_name=event_data.get("process_name"),
                user=event_data.get("user"),
                raw_payload=json.dumps(event_data.get("raw_payload", {})),
            )
            session.add(event)
            session.commit()

    def get_recent_events(self, limit: int = 100, event_type: Optional[str] = None) -> list[dict]:
        """Get recent events from the log."""
        with self.get_session() as session:
            query = session.query(EventLogModel).order_by(EventLogModel.timestamp.desc())
            if event_type:
                query = query.filter(EventLogModel.event_type == event_type)
            events = query.limit(limit).all()
            return [e.to_dict() for e in events]

    def cleanup_old_events(self, retention_hours: int = 24):
        """Remove events older than retention period."""
        with self.get_session() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=retention_hours)
            deleted = session.query(EventLogModel).filter(
                EventLogModel.timestamp < cutoff
            ).delete()
            session.commit()
            if deleted:
                logger.info(f"Cleaned up {deleted} old events (retention: {retention_hours}h)")
