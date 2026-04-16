"""
SENTINEL-X API Pydantic Schemas
Request/Response models for all REST endpoints.
"""
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# ─── Alert Schemas ──────────────────────────────────────

class AlertBase(BaseModel):
    alert_id: str = Field(alias="id", default="")
    timestamp: Optional[str] = None
    rule_id: str = ""
    rule_name: str = ""
    severity: str = ""
    confidence: float = 0.0
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    target_host: Optional[str] = None
    event_count: int = 0
    time_window_seconds: int = 0
    mitre_tech: Optional[str] = None
    mitre_tactic: Optional[str] = None
    correlated_rules: Optional[str] = None
    narrative: Optional[str] = None
    evidence: Optional[str] = None
    status: str = "open"

    class Config:
        populate_by_name = True


class AlertDetail(AlertBase):
    actions: list[dict] = []
    mitre_info: Optional[dict] = None


class AlertListResponse(BaseModel):
    alerts: list[dict]
    total: int
    offset: int
    limit: int


class AlertStatsResponse(BaseModel):
    total: int
    by_severity: dict
    by_status: dict


# ─── Action Schemas ─────────────────────────────────────

class ActionResponse(BaseModel):
    action_id: str
    alert_id: str
    action_type: str
    command: str
    justification: str
    status: str
    target: str = ""
    reversible: bool = False


class ActionApproval(BaseModel):
    status: str  # approved | skipped


class ActionResult(BaseModel):
    action_id: str
    status: str
    success: bool
    output: str = ""
    error: str = ""


# ─── Metrics Schemas ────────────────────────────────────

class SystemMetrics(BaseModel):
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_total_mb: float
    disk_percent: float
    net_bytes_sent: int
    net_bytes_recv: int
    net_connections: int
    process_count: int
    uptime_seconds: float


class ThreatLevel(BaseModel):
    level: str  # low | medium | high | critical
    open_alerts: int
    critical_count: int
    high_count: int
    score: float


# ─── Config Schemas ─────────────────────────────────────

class RuleConfig(BaseModel):
    id: str
    name: str
    severity: str
    enabled: bool
    mitre_technique: str
    confidence_base: float


class RuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    confidence_base: Optional[float] = None


# ─── Status Schema ──────────────────────────────────────

class SystemStatus(BaseModel):
    status: str  # running | stopped
    platform: str
    hostname: str
    uptime_seconds: float
    agent_running: bool
    agent_events_collected: int
    detection_rules_active: int
    detection_windows_active: int
    correlation_pending: int
    correlation_total: int
    llm_available: bool
    llm_provider: str
    db_backend: str
    queue_depth: int


# ─── WebSocket Message Schemas ──────────────────────────

class WSAlertMessage(BaseModel):
    type: str = "alert"
    alert_id: str
    timestamp: str
    rule_name: str
    severity: str
    confidence: float
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    mitre_technique: str = ""
    mitre_tactic: str = ""
    narrative: Optional[dict] = None
    actions: list[dict] = []
    is_correlated: bool = False
    correlation_name: Optional[str] = None


class WSMetricsMessage(BaseModel):
    type: str = "metrics"
    cpu_percent: float
    memory_percent: float
    net_bytes_sent: int
    net_bytes_recv: int
    net_connections: int
    timestamp: str
