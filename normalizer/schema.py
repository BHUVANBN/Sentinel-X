"""
SENTINEL-X Normalized Event Schema
Based on Elastic Common Schema (ECS) — platform-independent event representation.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
from enum import Enum


class RawEvent(BaseModel):
    """Raw event produced by OS monitoring agents before normalization."""
    source: str               # e.g. 'linux_auth', 'psutil_process', 'windows_security_log'
    event_type: str           # e.g. 'login_failure', 'process_spawn', 'network_connect'
    raw: dict                 # Original OS event payload
    timestamp: str            # ISO 8601 timestamp string


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class NormalizedEvent(BaseModel):
    """
    Platform-independent normalized event.
    All detection, correlation, and response logic operates on this schema.
    Inspired by Elastic Common Schema (ECS).
    """
    # ─── Identity ───────────────────────────────
    event_id: str = Field(description="UUID4 unique event identifier")
    timestamp: datetime = Field(description="Event timestamp in UTC")
    platform: str = Field(description="Source platform: linux | windows | macos")
    hostname: str = Field(description="Hostname of the monitored machine")

    # ─── Classification ─────────────────────────
    event_type: str = Field(description="Event type: login_failure | process_spawn | network_connect | file_change | ...")
    category: str = Field(description="ECS category: authentication | process | network | file")
    action: str = Field(description="Event action: attempt | success | failure | start | stop")
    outcome: str = Field(description="Event outcome: success | failure | unknown")

    # ─── Actor ──────────────────────────────────
    user: Optional[str] = None
    uid: Optional[int] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    command_line: Optional[str] = None

    # ─── Network ────────────────────────────────
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    source_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None

    # ─── File ───────────────────────────────────
    file_path: Optional[str] = None
    file_action: Optional[str] = None  # created | modified | deleted | renamed

    # ─── HTTP (Application Layer) ───────────────
    http_method: Optional[str] = None      # GET, POST, ...
    http_url: Optional[str] = None          # /api/login
    http_status_code: Optional[int] = None  # 200, 401
    http_user_agent: Optional[str] = None
    http_payload_size: Optional[int] = None

    # ─── Raw ────────────────────────────────────
    raw_source: str = Field(description="Which agent/collector produced this event")
    raw_payload: dict = Field(default_factory=dict, description="Original OS event for forensics")


    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()}
    )
