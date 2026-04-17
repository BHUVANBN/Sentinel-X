import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Shield, Activity, Bell, Settings, Radio, Eye, Zap,
  AlertTriangle, ShieldAlert, Target, Cpu,
  Clock, Check, X, Play,
  Search, BarChart3, Globe, Database
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';
import * as api from './api';

// ─── Toast System ──────────────────────────────────────

interface Toast {
  id: string;
  message: string;
  type: 'success' | 'error' | 'info' | 'warning';
}

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[], onDismiss: (id: string) => void }) {
  return (
    <div className="toast-container">
      {toasts.map(toast => (
        <div key={toast.id} className={`toast ${toast.type}`} onClick={() => onDismiss(toast.id)}>
          <div className="toast-content">
            {toast.type === 'success' && <Check size={14} />}
            {toast.type === 'error' && <AlertTriangle size={14} />}
            {toast.type === 'info' && <Radio size={14} />}
            <span>{toast.message}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Types ─────────────────────────────────────────────

interface Alert {
  id: string; timestamp: string; rule_id: string; rule_name: string;
  severity: string; confidence: number; source_ip: string | null;
  target_host: string | null; event_count: number; time_window_seconds: number;
  mitre_tech: string | null; mitre_tactic: string | null;
  correlated_rules: string | null; narrative: string | null;
  evidence: string | null; status: string;
}

interface WSAlert {
  alert_id: string; timestamp: string; rule_name: string; severity: string;
  confidence: number; source_ip: string | null; dest_ip: string | null;
  mitre_technique: string; mitre_tactic: string;
  narrative: any; actions: any[]; is_correlated: boolean;
  correlation_name: string | null;
}

interface Metrics {
  cpu_percent: number; memory_percent: number; net_bytes_sent: number;
  net_bytes_recv: number; net_connections: number; timestamp: string;
}

// ─── Severity Helpers ──────────────────────────────────

// Severity color constants for charts
//const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const CHART_COLORS = ['#ef4444', '#f59e0b', '#3b82f6', '#22c55e'];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

function timeAgo(ts: string): string {
  const diff = (Date.now() - new Date(ts).getTime()) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  return `${h}h ${m}m ${s}s`;
}

// ─── ThreatOrb Component ───────────────────────────────

function ThreatOrb({ level, score }: { level: string; score: number }) {
  return (
    <div style={{ textAlign: 'center' }}>
      <div className={`threat-orb ${level}`}>
        {level.toUpperCase()}
      </div>
      <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: 4 }}>
        Threat Score: {score}/100
      </div>
    </div>
  );
}

// ─── SeverityBadge ─────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toLowerCase() || 'low';
  return <span className={`severity-badge ${s}`}>● {s}</span>;
}

// ─── Metric Card ───────────────────────────────────────

function MetricCard({ label, value, sub, color }: {
  label: string; value: string | number; sub?: string; color: string;
}) {
  return (
    <div className={`metric-card ${color}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {sub && <div className="metric-sub">{sub}</div>}
    </div>
  );
}

// ─── Alert Card ────────────────────────────────────────

function AlertCard({ alert, isNew, onClick }: {
  alert: Alert | WSAlert; isNew?: boolean; onClick?: () => void;
}) {
  const sev = ('severity' in alert ? alert.severity : 'medium').toLowerCase();
  const ruleName = 'rule_name' in alert ? alert.rule_name : '';
  const ts = alert.timestamp;
  const sourceIp = alert.source_ip || 'N/A';
  const mitre = ('mitre_tech' in alert ? alert.mitre_tech : ('mitre_technique' in alert ? (alert as WSAlert).mitre_technique : '')) || '';
  const evtCount = 'event_count' in alert ? alert.event_count : 0;

  let narrativeObj: any = null;
  if ('narrative' in alert && alert.narrative) {
    try {
      narrativeObj = typeof alert.narrative === 'string' ? JSON.parse(alert.narrative) : alert.narrative;
    } catch { /* */ }
  }

  return (
    <div className={`alert-card ${sev} ${isNew ? 'new' : ''}`} onClick={onClick}>
      <div className="alert-card-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <SeverityBadge severity={sev} />
          <span className="alert-card-title">{ruleName}</span>
        </div>
        <span className="alert-card-time">{timeAgo(ts)}</span>
      </div>
      {narrativeObj?.what_happened && (
        <div className="alert-card-body">{narrativeObj.what_happened}</div>
      )}
      <div className="alert-card-meta">
        {sourceIp !== 'N/A' && <span className="meta-tag"><Globe size={10} /> {sourceIp}</span>}
        {mitre && <span className="meta-tag mitre"><Target size={10} /> {mitre}</span>}
        {evtCount > 0 && <span className="meta-tag"><Activity size={10} /> {evtCount} events</span>}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// ─── PAGES ─────────────────────────────────────────────
// ═══════════════════════════════════════════════════════

// ─── Dashboard Page ────────────────────────────────────

function DashboardPage({ notify }: { notify: any }) {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [metricsHistory, setMetricsHistory] = useState<any[]>([]);
  const [threatLevel, setThreatLevel] = useState<any>(null);
  const [stats, setStats] = useState<any>(null);
  const [liveAlerts, setLiveAlerts] = useState<WSAlert[]>([]);
  const [status, setStatus] = useState<any>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const alertWsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    // Initial data fetch
    api.fetchThreatLevel().then(setThreatLevel).catch(() => {});
    api.fetchAlertStats().then(setStats).catch(() => {});
    api.fetchStatus().then(setStatus).catch(() => {});

    const interval = setInterval(() => {
      api.fetchThreatLevel().then(setThreatLevel).catch(() => {});
      api.fetchAlertStats().then(setStats).catch(() => {});
      api.fetchStatus().then(setStatus).catch(() => {});
    }, 5000);

    // Metrics WebSocket
    wsRef.current = api.connectMetricsWS((data) => {
      setMetrics(data);
      setMetricsHistory(prev => {
        const next = [...prev, {
          time: new Date(data.timestamp).toLocaleTimeString(),
          cpu: data.cpu_percent,
          mem: data.memory_percent,
          net: data.net_connections,
        }];
        return next.slice(-60);
      });
    });

    // Alert WebSocket
    alertWsRef.current = api.connectAlertWS((data) => {
      setLiveAlerts(prev => [data, ...prev].slice(0, 50));
    });

    return () => {
      clearInterval(interval);
      wsRef.current?.close();
      alertWsRef.current?.close();
    };
  }, []);

  const sevData = stats ? [
    { name: 'Critical', value: stats.by_severity?.critical || 0 },
    { name: 'High', value: stats.by_severity?.high || 0 },
    { name: 'Medium', value: stats.by_severity?.medium || 0 },
    { name: 'Low', value: stats.by_severity?.low || 0 },
  ].filter(d => d.value > 0) : [];

  return (
    <>
      <div className="page-header">
        <div>
          <h2><Radio size={20} style={{ verticalAlign: 'middle', marginRight: 8 }} />Live Monitor</h2>
          <div className="subtitle">Real-time system metrics and threat detection</div>
        </div>
        <div className="header-actions">
          <button className="btn btn-primary btn-sm" onClick={() => {
            api.simulateAttack('brute_force');
            notify?.('Simulation started: SSH Brute Force', 'info');
          }}>
            <Zap size={12} /> Simulate Attack
          </button>
        </div>
      </div>
      <div className="page-body">
        {/* Metrics Bar */}
        <div className="metrics-grid">
          <MetricCard label="CPU Usage" value={`${metrics?.cpu_percent?.toFixed(1) || '0'}%`}
            sub="Current utilization" color="cyan" />
          <MetricCard label="Memory" value={`${metrics?.memory_percent?.toFixed(1) || '0'}%`}
            sub="RAM utilization" color="blue" />
          <MetricCard label="Network" value={metrics ? formatBytes(metrics.net_bytes_sent) : '0 B'}
            sub={`${metrics?.net_connections || 0} active connections`} color="green" />
          <MetricCard label="Open Alerts"
            value={stats?.by_status?.open || 0}
            sub={`${stats?.total || 0} total`} color="red" />
          <MetricCard label="Events Collected"
            value={status?.agent_events_collected?.toLocaleString() || '0'}
            sub={`Queue: ${status?.queue_depth || 0}`} color="amber" />
        </div>

        <div className="grid-3">
          {/* Main Area — Charts + Live Feed */}
          <div>
            {/* CPU/Memory Chart */}
            <div className="chart-container" style={{ marginBottom: 20 }}>
              <div className="card-header">
                <span className="card-title"><Activity size={14} /> System Performance</span>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={metricsHistory}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 10 }} interval="preserveStartEnd" />
                  <YAxis tick={{ fill: '#64748b', fontSize: 10 }} domain={[0, 100]} />
                  <Tooltip
                    contentStyle={{ background: '#151d2e', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                    labelStyle={{ color: '#94a3b8' }}
                  />
                  <Area type="monotone" dataKey="cpu" name="CPU %" stroke="#06b6d4" fill="rgba(6,182,212,0.1)" strokeWidth={2} />
                  <Area type="monotone" dataKey="mem" name="Memory %" stroke="#6366f1" fill="rgba(99,102,241,0.1)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Live Alert Feed */}
            <div className="card">
              <div className="card-header">
                <span className="card-title"><Bell size={14} /> Live Alert Feed</span>
                <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
                  {liveAlerts.length} alerts in session
                </span>
              </div>
              <div className="alert-feed">
                {liveAlerts.length === 0 ? (
                  <div className="empty-state">
                    <div className="icon"><ShieldAlert size={48} /></div>
                    <h3>No alerts yet</h3>
                    <p>System is monitoring. Alerts will appear here in real-time.</p>
                  </div>
                ) : (
                  liveAlerts.slice(0, 10).map((a, i) => (
                    <AlertCard key={a.alert_id || i} alert={a} isNew={i === 0} />
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Sidebar — Threat Level, Stats */}
          <div>
            {/* Threat Level */}
            <div className="card" style={{ marginBottom: 20, textAlign: 'center' }}>
              <div className="card-header" style={{ justifyContent: 'center' }}>
                <span className="card-title"><ShieldAlert size={14} /> Threat Level</span>
              </div>
              {threatLevel ? (
                <ThreatOrb level={threatLevel.level} score={threatLevel.score} />
              ) : (
                <ThreatOrb level="low" score={0} />
              )}
              {threatLevel && (
                <div style={{ marginTop: 12, fontSize: 12, color: 'var(--text-secondary)' }}>
                  <div>{threatLevel.critical_count} critical · {threatLevel.high_count} high</div>
                  <div style={{ color: 'var(--text-tertiary)', marginTop: 4 }}>
                    {threatLevel.open_alerts} open alerts
                  </div>
                </div>
              )}
            </div>

            {/* Alert Distribution */}
            {sevData.length > 0 && (
              <div className="card" style={{ marginBottom: 20 }}>
                <div className="card-header">
                  <span className="card-title"><BarChart3 size={14} /> Alert Distribution</span>
                </div>
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie data={sevData} cx="50%" cy="50%" innerRadius={40} outerRadius={70}
                      paddingAngle={4} dataKey="value">
                      {sevData.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#151d2e', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ display: 'flex', justifyContent: 'center', gap: 16, flexWrap: 'wrap' }}>
                  {sevData.map((d, i) => (
                    <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
                      <div style={{ width: 8, height: 8, borderRadius: '50%', background: CHART_COLORS[i] }} />
                      <span style={{ color: 'var(--text-tertiary)' }}>{d.name}: {d.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* System Status */}
            <div className="card">
              <div className="card-header">
                <span className="card-title"><Cpu size={14} /> System Status</span>
              </div>
              {status && (
                <div style={{ fontSize: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-tertiary)' }}>Platform</span>
                    <span className="mono">{status.platform}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-tertiary)' }}>Uptime</span>
                    <span className="mono">{formatUptime(status.uptime_seconds)}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-tertiary)' }}>Agent</span>
                    <span style={{ color: status.agent_running ? 'var(--success)' : 'var(--critical)' }}>
                      {status.agent_running ? '● Running' : '● Stopped'}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-tertiary)' }}>Detection Rules</span>
                    <span className="mono">{status.detection_rules_active}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-tertiary)' }}>Correlations</span>
                    <span className="mono">{status.correlation_total}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-tertiary)' }}>LLM</span>
                    <span style={{ color: status.llm_available ? 'var(--success)' : 'var(--warning)' }}>
                      {status.llm_available ? `● ${status.llm_provider}` : '○ Template mode'}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Alerts Page ───────────────────────────────────────

function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<any>(null);
  const [page, setPage] = useState(0);
  const limit = 20;

  const loadAlerts = useCallback(() => {
    api.fetchAlerts({
      limit, offset: page * limit,
      severity: severity || undefined, status: statusFilter || undefined
    }).then(data => { setAlerts(data.alerts); setTotal(data.total); });
  }, [page, severity, statusFilter]);

  useEffect(() => { loadAlerts(); }, [loadAlerts]);
  useEffect(() => {
    const iv = setInterval(loadAlerts, 10000);
    return () => clearInterval(iv);
  }, [loadAlerts]);

  useEffect(() => {
    if (selected) {
      api.fetchAlertDetail(selected).then(setDetail);
    } else {
      setDetail(null);
    }
  }, [selected]);

  const filtered = search
    ? alerts.filter(a =>
        a.rule_name.toLowerCase().includes(search.toLowerCase()) ||
        (a.source_ip || '').includes(search) ||
        (a.mitre_tech || '').toLowerCase().includes(search.toLowerCase())
      )
    : alerts;

  let narrativeObj: any = null;
  if (detail?.narrative) {
    try { narrativeObj = typeof detail.narrative === 'string' ? JSON.parse(detail.narrative) : detail.narrative; }
    catch { /* */ }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2><Bell size={20} style={{ verticalAlign: 'middle', marginRight: 8 }} />Alert History</h2>
          <div className="subtitle">{total} total alerts</div>
        </div>
      </div>
      <div className="page-body">
        <div className="filters-bar">
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: 8, color: 'var(--text-muted)' }} />
            <input className="filter-input" placeholder="Search alerts..." value={search}
              onChange={e => setSearch(e.target.value)} style={{ paddingLeft: 30 }} />
          </div>
          <select className="filter-select" value={severity} onChange={e => { setSeverity(e.target.value); setPage(0); }}>
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select className="filter-select" value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(0); }}>
            <option value="">All Status</option>
            <option value="open">Open</option>
            <option value="responded">Responded</option>
            <option value="closed">Closed</option>
          </select>
        </div>

        <div className="grid-2">
          {/* Alert List */}
          <div className="card" style={{ maxHeight: '75vh', overflowY: 'auto' }}>
            {filtered.length === 0 ? (
              <div className="empty-state"><h3>No alerts found</h3><p>Adjust filters or wait for incoming alerts.</p></div>
            ) : (
              <div className="alert-feed">
                {filtered.map(a => (
                  <AlertCard key={a.id} alert={a} onClick={() => setSelected(a.id)} />
                ))}
              </div>
            )}
            {total > limit && (
              <div style={{ display: 'flex', justifyContent: 'center', gap: 10, marginTop: 16 }}>
                <button className="btn btn-ghost btn-sm" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Previous</button>
                <span style={{ fontSize: 12, color: 'var(--text-tertiary)', lineHeight: '28px' }}>
                  Page {page + 1} of {Math.ceil(total / limit)}
                </span>
                <button className="btn btn-ghost btn-sm" disabled={(page + 1) * limit >= total} onClick={() => setPage(p => p + 1)}>Next</button>
              </div>
            )}
          </div>

          {/* Alert Detail */}
          <div>
            {detail ? (
              <div className="card">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                  <div>
                    <SeverityBadge severity={detail.severity} />
                    <h3 style={{ fontSize: 16, fontWeight: 700, marginTop: 8 }}>{detail.rule_name}</h3>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    {detail.status === 'open' && (
                      <button className="btn btn-ghost btn-sm" onClick={() => { api.closeAlert(detail.id); loadAlerts(); setSelected(null); }}>
                        <X size={12} /> Close
                      </button>
                    )}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
                  <span className="meta-tag"><Clock size={10} /> {new Date(detail.timestamp).toLocaleString()}</span>
                  {detail.source_ip && <span className="meta-tag"><Globe size={10} /> {detail.source_ip}</span>}
                  {detail.mitre_tech && <span className="meta-tag mitre"><Target size={10} /> {detail.mitre_tech}</span>}
                  <span className="meta-tag"><Activity size={10} /> {detail.event_count} events</span>
                  <span className="meta-tag"><Shield size={10} /> {(detail.confidence * 100).toFixed(0)}% confidence</span>
                </div>

                {/* Narrative */}
                {narrativeObj && (
                  <div className="narrative-card">
                    {narrativeObj.what_happened && (
                      <div className="narrative-section">
                        <div className="narrative-label">What Happened</div>
                        <div className="narrative-text">{narrativeObj.what_happened}</div>
                      </div>
                    )}
                    {narrativeObj.why_suspicious && (
                      <div className="narrative-section">
                        <div className="narrative-label">Why Suspicious</div>
                        <div className="narrative-text">{narrativeObj.why_suspicious}</div>
                      </div>
                    )}
                    {narrativeObj.attacker_goal && (
                      <div className="narrative-section">
                        <div className="narrative-label">Attacker Goal</div>
                        <div className="narrative-text">{narrativeObj.attacker_goal}</div>
                      </div>
                    )}
                    {narrativeObj.severity_reason && (
                      <div className="narrative-section">
                        <div className="narrative-label">Severity Reason</div>
                        <div className="narrative-text">{narrativeObj.severity_reason}</div>
                      </div>
                    )}
                    {narrativeObj.recommended_actions && (
                      <div className="narrative-section">
                        <div className="narrative-label">Recommended Actions</div>
                        <ul style={{ margin: 0, paddingLeft: 16 }}>
                          {narrativeObj.recommended_actions.map((a: string, i: number) => (
                            <li key={i} className="narrative-text">{a}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                {/* MITRE Info */}
                {detail.mitre_info && (
                  <div style={{ marginTop: 16 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
                      MITRE ATT&CK
                    </div>
                    <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-primary)', borderRadius: 'var(--radius-md)', padding: 12 }}>
                      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>{detail.mitre_info.name}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginBottom: 8 }}>
                        {detail.mitre_info.tactic} · {detail.mitre_info.id}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                        {detail.mitre_info.description?.substring(0, 300)}...
                      </div>
                    </div>
                  </div>
                )}

                {/* Actions */}
                {detail.actions?.length > 0 && (
                  <div style={{ marginTop: 16 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
                      Response Actions
                    </div>
                    <div className="response-actions">
                      {detail.actions.map((action: any) => (
                        <div key={action.id} className="action-card">
                          <div className="action-info">
                            <div className="action-type">{action.action_type.replace('_', ' ').toUpperCase()}</div>
                            <div className="action-command">{action.command}</div>
                            <div className="action-justification">{action.justification}</div>
                          </div>
                          <div className="action-buttons">
                            {action.status === 'pending' ? (
                              <>
                                <button className="btn btn-success btn-sm" onClick={() => api.approveAction(action.id).then(loadAlerts)}>
                                  <Check size={12} /> Approve
                                </button>
                                <button className="btn btn-ghost btn-sm" onClick={() => api.skipAction(action.id).then(loadAlerts)}>
                                  <X size={12} /> Skip
                                </button>
                              </>
                            ) : (
                              <span className="meta-tag">{action.status}</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="card">
                <div className="empty-state">
                  <div className="icon"><Eye size={48} /></div>
                  <h3>Select an alert</h3>
                  <p>Click on an alert to view details, narrative, and response actions.</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Response Center Page ──────────────────────────────

function ResponsePage() {
  const [pending, setPending] = useState<any[]>([]);
  const [history, setHistory] = useState<any[]>([]);

  const load = useCallback(() => {
    api.fetchPendingActions().then(setPending);
    api.fetchAlerts({ limit: 50, status: 'responded' }).then(d => setHistory(d.alerts || []));
  }, []);

  useEffect(() => { load(); const iv = setInterval(load, 5000); return () => clearInterval(iv); }, [load]);

  return (
    <>
      <div className="page-header">
        <div>
          <h2><Zap size={20} style={{ verticalAlign: 'middle', marginRight: 8 }} />Response Center</h2>
          <div className="subtitle">Approve or skip proposed mitigation actions</div>
        </div>
      </div>
      <div className="page-body">
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header">
            <span className="card-title"><AlertTriangle size={14} /> Pending Approval ({pending.length})</span>
          </div>
          {pending.length === 0 ? (
            <div className="empty-state">
              <div className="icon"><Shield size={48} /></div>
              <h3>No pending actions</h3>
              <p>All proposed response actions have been processed.</p>
            </div>
          ) : (
            <div className="response-actions">
              {pending.map(action => (
                <div key={action.id} className="action-card">
                  <div className="action-info">
                    <div className="action-type">{action.action_type.replace('_', ' ').toUpperCase()}</div>
                    <div className="action-command">{action.command}</div>
                    <div className="action-justification">{action.justification}</div>
                    <div style={{ marginTop: 4 }}>
                      <span className="meta-tag" style={{ fontSize: 9 }}>Alert: {action.alert_id?.substring(0, 8)}...</span>
                    </div>
                  </div>
                  <div className="action-buttons">
                    <button className="btn btn-success btn-sm" onClick={() => api.approveAction(action.id).then(load)}>
                      <Check size={12} /> Approve & Execute
                    </button>
                    <button className="btn btn-ghost btn-sm" onClick={() => api.skipAction(action.id).then(load)}>
                      <X size={12} /> Skip
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Response History */}
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Clock size={14} /> Response History</span>
          </div>
          {history.length === 0 ? (
            <div className="empty-state">
              <p>No responded alerts yet.</p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr><th>Time</th><th>Alert</th><th>Severity</th><th>Status</th></tr>
              </thead>
              <tbody>
                {history.map(a => (
                  <tr key={a.id}>
                    <td className="mono">{new Date(a.timestamp).toLocaleString()}</td>
                    <td>{a.rule_name}</td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td><span className="meta-tag">{a.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}

// ─── MITRE Heatmap Page ────────────────────────────────

function MitrePage() {
  const [techniques, setTechniques] = useState<Record<string, any>>({});
  const [alerts, setAlerts] = useState<Alert[]>([]);

  useEffect(() => {
    api.fetchMitre().then(setTechniques);
    api.fetchAlerts({ limit: 200 }).then(d => setAlerts(d.alerts || []));
  }, []);

  const detectedTechniques = new Set(alerts.map(a => a.mitre_tech).filter(Boolean));

  return (
    <>
      <div className="page-header">
        <div>
          <h2><Target size={20} style={{ verticalAlign: 'middle', marginRight: 8 }} />MITRE ATT&CK Matrix</h2>
          <div className="subtitle">Detected techniques mapped to ATT&CK framework</div>
        </div>
      </div>
      <div className="page-body">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Technique Coverage</span>
            <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
              {detectedTechniques.size} / {Object.keys(techniques).length} techniques detected
            </span>
          </div>
          <div className="mitre-grid">
            {Object.entries(techniques).map(([id, tech]: [string, any]) => (
              <div key={id} className={`mitre-cell ${detectedTechniques.has(id) ? 'detected' : ''}`}>
                <div className="technique-id">{id}</div>
                <div className="technique-name">{tech.name}</div>
                {detectedTechniques.has(id) && (
                  <div style={{ marginTop: 4, fontSize: 9, color: 'var(--critical)' }}>
                    ● DETECTED
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Config Page ───────────────────────────────────────

function ConfigPage({ notify }: { notify: any }) {
  const [rules, setRules] = useState<any[]>([]);
  const [_status, setStatus] = useState<any>(null);

  useEffect(() => {
    api.fetchRules().then(setRules);
    api.fetchStatus().then(setStatus);
  }, []);

  const toggleRule = (ruleId: string, enabled: boolean) => {
    api.updateRule(ruleId, { enabled: !enabled }).then(() => api.fetchRules().then(setRules));
  };

  const simTypes = [
    { type: 'brute_force', name: 'Brute Force / Credential Stuffing', severity: 'high' },
    { type: 'lateral_movement', name: 'Lateral Movement', severity: 'high' },
    { type: 'exfiltration', name: 'Data Exfiltration', severity: 'critical' },
    { type: 'c2_beacon', name: 'C2 Beacon', severity: 'critical' },
    { type: 'advanced_incident', name: 'Multi-Phase APT (Chain)', severity: 'critical' },
    { type: 'false_positive', name: 'Admin Backup (False Positive)', severity: 'medium' },
  ];

  return (
    <>
      <div className="page-header">
        <div>
          <h2><Settings size={20} style={{ verticalAlign: 'middle', marginRight: 8 }} />Configuration</h2>
          <div className="subtitle">Detection rules and attack simulations</div>
        </div>
      </div>
      <div className="page-body">
        <div className="grid-2">
          {/* Detection Rules */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><Shield size={14} /> Detection Rules</span>
            </div>
            <table className="data-table">
              <thead>
                <tr><th>ID</th><th>Rule Name</th><th>Severity</th><th>MITRE</th><th>Status</th></tr>
              </thead>
              <tbody>
                {rules.map(r => (
                  <tr key={r.id}>
                    <td className="mono">{r.id}</td>
                    <td>{r.name}</td>
                    <td><SeverityBadge severity={r.severity} /></td>
                    <td className="mono">{r.mitre_technique}</td>
                    <td>
                      <button
                        className={`btn btn-sm ${r.enabled ? 'btn-success' : 'btn-ghost'}`}
                        onClick={() => toggleRule(r.id, r.enabled)}
                      >
                        {r.enabled ? '● Enabled' : '○ Disabled'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          </div>

          <div>
            {/* Attack Simulations */}
            <div className="card" style={{ marginBottom: 20 }}>
              <div className="card-header">
                <span className="card-title"><Zap size={14} /> Attack Simulations</span>
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 16 }}>
                Inject synthetic events to test detection rules. No real attack traffic is generated.
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {simTypes.map(sim => (
                  <div key={sim.type} style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    background: 'var(--bg-input)', border: '1px solid var(--border-primary)',
                    borderRadius: 'var(--radius-md)', padding: '10px 14px'
                  }}>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 600 }}>{sim.name}</div>
                      <SeverityBadge severity={sim.severity} />
                    </div>
                    <button className="btn btn-primary btn-sm" onClick={() => {
                    api.simulateAttack(sim.type);
                    notify?.(`Simulation started: ${sim.name}`, 'info');
                  }}>
                      <Play size={12} /> Run
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Real Datasets */}
            <div className="card">
              <div className="card-header">
                <span className="card-title"><Database size={14} /> Real-World Datasets</span>
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 16 }}>
                Ingest historic threat data (CICIDS 2017 / UNSW-NB15) into the detection engine.
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ background: 'var(--bg-input)', padding: 12, borderRadius: 8, border: '1px solid var(--border-primary)' }}>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>CICIDS 2017 (IDS Dataset)</div>
                  <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginBottom: 10 }}>Infiltrate, Botnet, and DoS scenarios</div>
                  <button className="btn btn-ghost btn-sm w-full" onClick={() => {
                    api.loadDataset({ type: 'cicids', max_rows: 1000 });
                    notify?.('Dataset ingestion started: CICIDS 2017', 'success');
                  }}>
                    <Play size={12} /> Load 1000 Rows
                  </button>
                </div>
                <div style={{ background: 'var(--bg-input)', padding: 12, borderRadius: 8, border: '1px solid var(--border-primary)' }}>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>UNSW-NB15</div>
                  <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginBottom: 10 }}>Modern network threat patterns</div>
                  <button className="btn btn-ghost btn-sm w-full" onClick={() => {
                    api.loadDataset({ type: 'unsw_nb15', max_rows: 1000 });
                    notify?.('Dataset ingestion started: UNSW-NB15', 'success');
                  }}>
                    <Play size={12} /> Load 1000 Rows
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}


// ═══════════════════════════════════════════════════════
// ─── MAIN APP ──────────────────────────────────────────
// ═══════════════════════════════════════════════════════

export default function App() {
  const [page, setPage] = useState<string>('dashboard');
  const [alertCount, setAlertCount] = useState(0);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const notify = (message: string, type: 'success' | 'error' | 'info' | 'warning' = 'info') => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000);
  };

  const dismissToast = (id: string) => setToasts(prev => prev.filter(t => t.id !== id));

  useEffect(() => {
    api.fetchAlertStats().then(s => setAlertCount(s?.by_status?.open || 0)).catch(() => {});
    const iv = setInterval(() => {
      api.fetchAlertStats().then(s => setAlertCount(s?.by_status?.open || 0)).catch(() => {});
    }, 10000);
    return () => clearInterval(iv);
  }, []);

  const navItems = [
    { id: 'dashboard', icon: <Radio size={16} />, label: 'Live Monitor' },
    { id: 'alerts', icon: <Bell size={16} />, label: 'Alerts', badge: alertCount > 0 ? alertCount : undefined },
    { id: 'response', icon: <Zap size={16} />, label: 'Response Center' },
    { id: 'mitre', icon: <Target size={16} />, label: 'MITRE ATT&CK' },
    { id: 'config', icon: <Settings size={16} />, label: 'Configuration' },
  ];

  return (
    <div className="app-layout">
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
      {/* Sidebar */}
      <nav className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <div className="logo-icon">SX</div>
            <div>
              <h1>SENTINEL-X</h1>
              <span>Threat Detection v1.0</span>
            </div>
          </div>
        </div>
        <div className="sidebar-nav">
          {navItems.map(item => (
            <div key={item.id}
              className={`nav-link ${page === item.id ? 'active' : ''}`}
              onClick={() => setPage(item.id)}>
              {item.icon}
              {item.label}
              {item.badge !== undefined && <span className="badge">{item.badge}</span>}
            </div>
          ))}
        </div>
        <div className="sidebar-status">
          <div className="status-indicator">
            <div className="status-dot" />
            <span>System Active · Monitoring</span>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="main-content">
        {page === 'dashboard' && <DashboardPage notify={notify} />}
        {page === 'alerts' && <AlertsPage />}
        {page === 'response' && <ResponsePage />}
        {page === 'mitre' && <MitrePage />}
        {page === 'config' && <ConfigPage notify={notify} />}
      </main>
    </div>
  );
}
