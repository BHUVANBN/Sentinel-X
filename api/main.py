"""
SENTINEL-X FastAPI Main Application
REST API + WebSocket hub for the React dashboard.
"""
import asyncio
import json
import logging
import os
import platform
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from api.models import (
    AlertListResponse, AlertStatsResponse, ActionApproval, ActionResult,
    SystemMetrics, ThreatLevel, SystemStatus, RuleConfig, RuleUpdate,
    WSAlertMessage, WSMetricsMessage
)
from config.loader import get_config
from storage.db import Database
from detection.rule_loader import load_all_rules
from detection.engine import DetectionEngine
from correlation.engine import CorrelationEngine, CorrelatedAlert
from explainability.narrator import Narrator
from explainability.mitre_mapper import MitreMapper
from response.engine import ResponseEngine
from normalizer.normalizer import Normalizer
from normalizer.schema import RawEvent

logger = logging.getLogger("sentinel.api")

# ─── Application Setup ─────────────────────────────────

app = FastAPI(
    title="SENTINEL-X",
    description="AI-Driven Threat Detection & Response System",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Global State ──────────────────────────────────────

class SentinelState:
    """Global application state."""
    def __init__(self):
        self.config = get_config()
        self.db = Database(self.config.db_url)
        self.db.init_db()
        self.normalizer = Normalizer()
        self.mitre_mapper = MitreMapper()
        
        # Core engines
        self.rules = load_all_rules(
            self.config.get('detection.rules_dir', 'detection/rules'),
            self.config.get('detection.enabled_rules', 'all'),
        )
        self.detection_engine = DetectionEngine(self.rules)
        self.correlation_engine = CorrelationEngine()
        self.narrator = Narrator(self.config.llm, self.mitre_mapper)
        self.response_engine = ResponseEngine()
        
        # Agents
        self.agent = None
        self.docker_agent = ContainerTelemetryAgent(self.event_queue)
        
        self.alert_subscribers: list[WebSocket] = []
        self.metrics_subscribers: list[WebSocket] = []
        self.start_time = time.time()
        self.agent_task: Optional[asyncio.Task] = None
        self.docker_agent_task: Optional[asyncio.Task] = None
        self.pipeline_task: Optional[asyncio.Task] = None
        self.metrics_task: Optional[asyncio.Task] = None
        self.test_mode = False

        # Pending response actions (in-memory)
        self.pending_actions: dict[str, dict] = {}


state = SentinelState()


# ─── Event Processing Pipeline ─────────────────────────

async def process_event_pipeline():
    """Main event processing pipeline — consumes events from queue."""
    logger.info("Event processing pipeline started")
    while True:
        try:
            raw_event: RawEvent = await state.event_queue.get()

            # Step 1: Normalize
            normalized = state.normalizer.normalize(raw_event)
            if not normalized:
                continue

            # Step 2: Log event
            try:
                state.db.log_event(normalized.model_dump())
            except Exception as e:
                logger.debug(f"Event logging error: {e}")

            # Step 3: Detection
            candidates = state.detection_engine.evaluate(normalized)

            # Dispatch non-blocking background task for heavy lifting (Narrative + Logic)
            asyncio.create_task(process_alert_async(state, candidates))
        except Exception as e:
            logger.error(f"Critical error in ingestion pipeline: {e}")
            await asyncio.sleep(1)


async def process_alert_async(state, candidates):
    """Heavy-lifting part of the pipeline: Narrative, DB, Response, and Push."""
    for candidate in candidates:
        try:
            # Step 4: Correlation
            correlated = state.correlation_engine.feed(candidate)

            # Step 5: Narrative (LLM call - can be slow)
            try:
                narrative = await state.narrator.narrate(correlated)
            except Exception as e:
                logger.error(f"Narrative generation error: {e}")
                narrative = {
                    "what_happened": f"Alert: {correlated.rule_name}",
                    "why_suspicious": "Detection rule triggered",
                    "attacker_objective": "Unknown",
                    "false_positive_indicators": "Review logs manually",
                    "fp_probability": 50,
                    "mitigation_playbook": [{"step": "Investigate", "command": "grep {source_ip} /var/log/syslog", "logic": "Check logs"}]
                }

            # Step 6: Response Engine suggestions
            alert_summary = {
                'alert_id': correlated.alert_id,
                'rule_id': correlated.rule_id,
                'severity': correlated.severity,
                'source_ip': correlated.source_ip,
                'dest_ip': correlated.dest_ip,
                'platform': correlated.platform,
            }
            response_actions = state.response_engine.suggest(alert_summary)

            # Step 7: Save to database
            try:
                # Prepare UI alert data
                alert_data = {
                    'alert_id': correlated.alert_id,
                    'timestamp': correlated.timestamp.isoformat(),
                    'rule_id': correlated.rule_id,
                    'rule_name': correlated.rule_name,
                    'severity': correlated.severity,
                    'confidence': correlated.confidence,
                    'source_ip': correlated.source_ip,
                    'dest_ip': correlated.dest_ip,
                    'event_count': correlated.event_count,
                    'mitre_technique': correlated.mitre_technique,
                    'mitre_tactic': correlated.mitre_tactic,
                    'narrative': narrative,
                    'evidence_summary': correlated.evidence_summary,
                }
                state.db.save_alert(alert_data)
                
                for action in response_actions:
                    action_data = {
                        'action_id': action.action_id,
                        'alert_id': correlated.alert_id,
                        'type': action.action_type,
                        'status': 'pending',
                        'command': action.command,
                        'justification': action.justification,
                        'timestamp': action.timestamp.isoformat(),
                    }
                    state.db.save_action(action_data)
                    state.pending_actions[action.action_id] = {
                        'action': action,
                        'alert_id': correlated.alert_id,
                    }
            except Exception as e:
                logger.error(f"Database save error: {e}")

            # Step 8: Push to WebSocket subscribers
            ws_message = WSAlertMessage(
                alert_id=correlated.alert_id,
                rule_name=correlated.rule_name,
                severity=correlated.severity,
                timestamp=correlated.timestamp.isoformat(),
                source_ip=correlated.source_ip,
                actions=[
                    {
                        'action_id': a.action_id,
                        'type': a.action_type,
                        'command': a.command,
                        'justification': a.justification,
                    }
                    for a in response_actions
                ],
                is_correlated=correlated.is_correlated,
                correlation_name=correlated.correlation_name,
                narrative=narrative
            )

            await broadcast_alert(ws_message)

            logger.info(
                f"[ALERT] {correlated.severity.upper()} — {correlated.rule_name} "
                f"(source: {correlated.source_ip}, events: {correlated.event_count})"
            )

        except Exception as e:
            logger.error(f"Error in background alert processing: {e}", exc_info=True)


async def broadcast_alert(message: WSAlertMessage):
    """Broadcast an alert to all WebSocket subscribers."""
    dead = []
    data = message.model_dump_json()
    for ws in state.alert_subscribers:
        try:
            await ws.send_text(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        state.alert_subscribers.remove(ws)


async def metrics_broadcaster():
    """Broadcast system metrics to subscribers every second."""
    while True:
        try:
            if state.metrics_subscribers:
                cpu = psutil.cpu_percent(interval=0)
                mem = psutil.virtual_memory()
                net = psutil.net_io_counters()
                conns = len(psutil.net_connections(kind='inet'))

                message = WSMetricsMessage(
                    cpu_percent=cpu,
                    memory_percent=mem.percent,
                    net_bytes_sent=net.bytes_sent,
                    net_bytes_recv=net.bytes_recv,
                    net_connections=conns,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )

                data = message.model_dump_json()
                dead = []
                for ws in state.metrics_subscribers:
                    try:
                        await ws.send_text(data)
                    except Exception:
                        dead.append(ws)
                for ws in dead:
                    state.metrics_subscribers.remove(ws)

        except Exception as e:
            logger.debug(f"Metrics broadcast error: {e}")

        await asyncio.sleep(1)


# ─── Lifecycle Events ──────────────────────────────────

@app.on_event("startup")
async def startup():
    """Start the event processing pipeline and OS agent."""
    logger.info("Starting SENTINEL-X...")

    # Start pipeline
    state.pipeline_task = asyncio.create_task(process_event_pipeline())

    # Start metrics broadcaster
    state.metrics_task = asyncio.create_task(metrics_broadcaster())

    # Start OS agent
    try:
        current_platform = platform.system().lower()
        if current_platform == 'linux':
            from agents.linux_agent import LinuxAgent
            state.agent = LinuxAgent(state.event_queue, state.config.poll_interval)
        elif current_platform == 'windows':
            from agents.windows_agent import WindowsAgent
            state.agent = WindowsAgent(state.event_queue, state.config.poll_interval)
        elif current_platform == 'darwin':
            from agents.macos_agent import MacOSAgent
            state.agent = MacOSAgent(state.event_queue, state.config.poll_interval)
        else:
            from agents.linux_agent import LinuxAgent
            state.agent = LinuxAgent(state.event_queue, state.config.poll_interval)

        state.agent_task = asyncio.create_task(state.agent.run())
        logger.info(f"OS agent started for platform: {current_platform}")
        
        # v3.0: Start Docker Telemetry Agent
        if state.docker_agent:
            state.docker_agent_task = asyncio.create_task(state.docker_agent.run())
            logger.info("Docker Telemetry agent started")

    except Exception as e:
        logger.error(f"Failed to start OS agent: {e}")

    logger.info("SENTINEL-X is running")


@app.on_event("shutdown")
async def shutdown():
    """Clean shutdown."""
    logger.info("Shutting down SENTINEL-X...")
    if state.agent:
        await state.agent.stop()
    if state.agent_task:
        state.agent_task.cancel()
    if state.docker_agent_task:
        state.docker_agent_task.cancel()
    if state.pipeline_task:
        state.pipeline_task.cancel()
    if state.metrics_task:
        state.metrics_task.cancel()


# ─── REST API Endpoints ────────────────────────────────

@app.get("/api/status")
async def get_status():
    """Get system status — agent, detection, correlation, LLM, DB."""
    uptime = time.time() - state.start_time
    detection_stats = state.detection_engine.get_stats()
    correlation_stats = state.correlation_engine.get_stats()

    return SystemStatus(
        status="running",
        platform=platform.system().lower(),
        hostname=socket.gethostname(),
        uptime_seconds=uptime,
        agent_running=state.agent.is_running if state.agent else False,
        agent_events_collected=state.agent.event_count if state.agent else 0,
        detection_rules_active=detection_stats['active_rules'],
        detection_windows_active=detection_stats['active_windows'],
        correlation_pending=correlation_stats['pending_candidates'],
        correlation_total=correlation_stats['total_correlations'],
        llm_available=state.narrator.is_llm_available,
        llm_provider=state.config.get('llm.provider', 'none'),
        db_backend=state.config.get('storage.backend', 'sqlite'),
        queue_depth=state.event_queue.qsize(),
    )


@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """Get paginated alert history."""
    alerts = state.db.get_alerts(limit=limit, offset=offset, severity=severity, status=status)
    total = state.db.get_alert_count(severity=severity)
    return AlertListResponse(alerts=alerts, total=total, offset=offset, limit=limit)


@app.get("/api/alerts/stats")
async def get_alert_stats():
    """Get alert statistics by severity and status."""
    stats = state.db.get_alert_stats()
    return AlertStatsResponse(**stats)


@app.get("/api/alerts/{alert_id}")
async def get_alert_detail(alert_id: str):
    """Get full alert detail including narrative and evidence."""
    alert = state.db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Enrich with MITRE data
    mitre_info = state.mitre_mapper.lookup(alert.get('mitre_tech', ''))
    alert['mitre_info'] = mitre_info
    return alert


@app.post("/api/alerts/{alert_id}/close")
async def close_alert(alert_id: str):
    """Close an alert."""
    success = state.db.update_alert_status(alert_id, "closed")
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "closed", "alert_id": alert_id}


@app.get("/api/actions/pending")
async def get_pending_actions():
    """Get all pending response actions."""
    return state.db.get_pending_actions()


@app.get("/api/actions/{alert_id}")
async def get_actions_for_alert(alert_id: str):
    """Get all actions for a specific alert."""
    return state.db.get_actions_for_alert(alert_id)


@app.post("/api/actions/{action_id}/approve")
async def approve_action(action_id: str):
    """Approve a pending response action."""
    action_data = state.pending_actions.get(action_id)
    if not action_data:
        # Try database
        state.db.update_action_status(action_id, "approved")
        return ActionResult(action_id=action_id, status="approved", success=True,
                          output="Action approved (not executed — manual execution required)")

    action = action_data['action']
    action.status = 'approved'

    # Execute the action
    result = state.response_engine.execute(action)

    # Update database
    state.db.update_action_status(
        action_id,
        "executed" if result.success else "failed",
        result=result.output or result.error
    )

    # Update alert status
    state.db.update_alert_status(action_data['alert_id'], "responded")

    return ActionResult(
        action_id=action_id,
        status=action.status,
        success=result.success,
        output=result.output,
        error=result.error,
    )


@app.post("/api/actions/{action_id}/skip")
async def skip_action(action_id: str):
    """Skip a proposed response action."""
    state.db.update_action_status(action_id, "skipped")
    if action_id in state.pending_actions:
        state.pending_actions[action_id]['action'].status = 'skipped'
    return {"action_id": action_id, "status": "skipped"}


@app.get("/api/metrics/live")
async def get_live_metrics():
    """Get current system metrics."""
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters()
    conns = len(psutil.net_connections(kind='inet'))
    uptime = time.time() - state.start_time

    return SystemMetrics(
        cpu_percent=cpu,
        memory_percent=mem.percent,
        memory_used_mb=mem.used / (1024 * 1024),
        memory_total_mb=mem.total / (1024 * 1024),
        disk_percent=disk.percent,
        net_bytes_sent=net.bytes_sent,
        net_bytes_recv=net.bytes_recv,
        net_connections=conns,
        process_count=len(psutil.pids()),
        uptime_seconds=uptime,
    )


@app.get("/api/metrics/threat-level")
async def get_threat_level():
    """Get current threat level based on open alerts."""
    stats = state.db.get_alert_stats()
    open_alerts = stats['by_status'].get('open', 0)
    critical = stats['by_severity'].get('critical', 0)
    high = stats['by_severity'].get('high', 0)

    # Calculate threat score
    score = critical * 40 + high * 20 + stats['by_severity'].get('medium', 0) * 5
    if score >= 100:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 10:
        level = "medium"
    else:
        level = "low"

    return ThreatLevel(
        level=level,
        open_alerts=open_alerts,
        critical_count=critical,
        high_count=high,
        score=min(score, 100),
    )


@app.get("/api/config/rules")
async def get_rules():
    """List all detection rules."""
    return [
        RuleConfig(
            id=r.id,
            name=r.name,
            severity=r.severity,
            enabled=r.enabled,
            mitre_technique=r.mitre_technique,
            confidence_base=r.confidence_base,
        )
        for r in state.rules
    ]


@app.put("/api/config/rules/{rule_id}")
async def update_rule(rule_id: str, update: RuleUpdate):
    """Update a detection rule's configuration."""
    for rule in state.rules:
        if rule.id == rule_id:
            if update.enabled is not None:
                rule.enabled = update.enabled
            if update.confidence_base is not None:
                rule.confidence_base = update.confidence_base
            # Rebuild detection engine
            state.detection_engine = DetectionEngine(state.rules)
            return {"status": "updated", "rule_id": rule_id}
    raise HTTPException(status_code=404, detail="Rule not found")


@app.get("/api/mitre/{technique_id}")
async def get_mitre_technique(technique_id: str):
    """Get MITRE ATT&CK technique detail."""
    return state.mitre_mapper.lookup(technique_id)


@app.get("/api/mitre")
async def get_all_mitre():
    """Get all MITRE ATT&CK techniques in the database."""
    return state.mitre_mapper.all_techniques


@app.get("/api/events/recent")
async def get_recent_events(
    limit: int = Query(100, ge=1, le=500),
    event_type: Optional[str] = Query(None),
):
    """Get recent events from the event log."""
    return state.db.get_recent_events(limit=limit, event_type=event_type)


# ─── Test/Simulation Endpoints ─────────────────────────

@app.post("/api/test/inject")
async def inject_test_event(event: dict):
    """Inject a test event into the processing pipeline."""
    raw = RawEvent(
        source=event.get('source', 'test'),
        event_type=event.get('event_type', 'test'),
        raw=event.get('raw', {}),
        timestamp=event.get('timestamp', datetime.now(timezone.utc).isoformat()),
    )
    await state.event_queue.put(raw)
    return {"status": "injected", "queue_depth": state.event_queue.qsize()}


@app.post("/api/test/simulate/{attack_type}")
async def simulate_attack(attack_type: str):
    """Trigger a predefined attack simulation."""
    from tests.sim import run_simulation
    count = await run_simulation(attack_type, state.event_queue)
    return {"status": "simulation_started", "attack_type": attack_type, "events_injected": count}


@app.post('/api/test/load-dataset')
async def load_dataset(data: dict):
    """Load a security dataset CSV into the pipeline."""
    from data.loader import DatasetLoader
    dataset_type = data.get('type', 'cicids')
    csv_path = data.get('path', f'data/cicids_{dataset_type}.csv')
    max_rows = data.get('max_rows', 500)
    speed = data.get('speed', 10.0)

    loader = DatasetLoader(state.event_queue, speed_multiplier=speed)
    if dataset_type == 'unsw_nb15':
        count = await loader.load_unsw_nb15(csv_path, max_rows)
    else:
        count = await loader.load_cicids(csv_path, max_rows)

    return {'status': 'loading', 'events_queued': count, 'stats': loader.stats}


@app.get('/api/test/datasets')
async def list_datasets():
    """List available dataset files."""
    import glob
    files = glob.glob('data/*.csv')
    return {
        'available': files,
        'download_instructions': {
            'CICIDS2017': 'https://www.unb.ca/cic/datasets/ids-2017.html',
            'UNSW-NB15': 'https://research.unsw.edu.au/projects/unsw-nb15-dataset',
        }
    }


# ─── WebSocket Endpoints ───────────────────────────────

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Real-time alert stream via WebSocket."""
    await websocket.accept()
    state.alert_subscribers.append(websocket)
    logger.info(f"Alert WebSocket connected ({len(state.alert_subscribers)} total)")

    try:
        while True:
            # Keep connection alive, listen for client messages
            data = await websocket.receive_text()
            # Client can send ping/pong
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        state.alert_subscribers.remove(websocket)
        logger.info(f"Alert WebSocket disconnected ({len(state.alert_subscribers)} total)")


@app.websocket("/ws/metrics")
async def websocket_metrics(websocket: WebSocket):
    """Real-time system metrics stream via WebSocket (1s interval)."""
    await websocket.accept()
    state.metrics_subscribers.append(websocket)
    logger.info(f"Metrics WebSocket connected ({len(state.metrics_subscribers)} total)")

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        state.metrics_subscribers.remove(websocket)
        logger.info(f"Metrics WebSocket disconnected ({len(state.metrics_subscribers)} total)")


# ─── Serve React Dashboard ─────────────────────────────

dashboard_path = Path(__file__).parent.parent / "dashboard" / "dist"

if dashboard_path.exists():
    app.mount("/assets", StaticFiles(directory=str(dashboard_path / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_dashboard(full_path: str):
        """Serve the React dashboard for all non-API routes."""
        file_path = dashboard_path / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(dashboard_path / "index.html"))
