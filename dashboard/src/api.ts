const API_BASE = '/api';
const WS_BASE = `ws://${window.location.host}`;

// ─── REST API ──────────────────────────────────────────

export async function fetchStatus() {
  const res = await fetch(`${API_BASE}/status`);
  return res.json();
}

export async function fetchAlerts(params: {
  limit?: number; offset?: number; severity?: string; status?: string;
} = {}) {
  const q = new URLSearchParams();
  if (params.limit) q.set('limit', String(params.limit));
  if (params.offset) q.set('offset', String(params.offset));
  if (params.severity) q.set('severity', params.severity);
  if (params.status) q.set('status', params.status);
  const res = await fetch(`${API_BASE}/alerts?${q}`);
  return res.json();
}

export async function fetchAlertDetail(id: string) {
  const res = await fetch(`${API_BASE}/alerts/${id}`);
  return res.json();
}

export async function fetchAlertStats() {
  const res = await fetch(`${API_BASE}/alerts/stats`);
  return res.json();
}

export async function closeAlert(id: string) {
  const res = await fetch(`${API_BASE}/alerts/${id}/close`, { method: 'POST' });
  return res.json();
}

export async function fetchPendingActions() {
  const res = await fetch(`${API_BASE}/actions/pending`);
  return res.json();
}

export async function approveAction(actionId: string) {
  const res = await fetch(`${API_BASE}/actions/${actionId}/approve`, { method: 'POST' });
  return res.json();
}

export async function skipAction(actionId: string) {
  const res = await fetch(`${API_BASE}/actions/${actionId}/skip`, { method: 'POST' });
  return res.json();
}

export async function fetchMetrics() {
  const res = await fetch(`${API_BASE}/metrics/live`);
  return res.json();
}

export async function fetchThreatLevel() {
  const res = await fetch(`${API_BASE}/metrics/threat-level`);
  return res.json();
}

export async function fetchRules() {
  const res = await fetch(`${API_BASE}/config/rules`);
  return res.json();
}

export async function updateRule(ruleId: string, data: { enabled?: boolean; confidence_base?: number }) {
  const res = await fetch(`${API_BASE}/config/rules/${ruleId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function fetchMitre(techniqueId?: string) {
  const url = techniqueId ? `${API_BASE}/mitre/${techniqueId}` : `${API_BASE}/mitre`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchRecentEvents(limit: number = 100) {
  const res = await fetch(`${API_BASE}/events/recent?limit=${limit}`);
  return res.json();
}

export async function simulateAttack(type: string) {
  const res = await fetch(`${API_BASE}/test/simulate/${type}`, { method: 'POST' });
  return res.json();
}

export async function loadDataset(data: { type: string; max_rows?: number; speed?: number }) {
  const res = await fetch(`${API_BASE}/test/load-dataset`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function fetchAvailableDatasets() {
  const res = await fetch(`${API_BASE}/test/datasets`);
  return res.json();
}

// ─── WebSocket ─────────────────────────────────────────

export function connectAlertWS(onMessage: (data: any) => void): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/ws/alerts`);
  ws.onopen = () => console.log('[WS] Alert stream connected');
  ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.type !== 'pong') onMessage(data);
    } catch { /* ignore parse errors */ }
  };
  ws.onclose = () => {
    console.log('[WS] Alert stream disconnected, reconnecting...');
    setTimeout(() => connectAlertWS(onMessage), 3000);
  };
  return ws;
}

export function connectMetricsWS(onMessage: (data: any) => void): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/ws/metrics`);
  ws.onopen = () => console.log('[WS] Metrics stream connected');
  ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.type !== 'pong') onMessage(data);
    } catch { /* ignore */ }
  };
  ws.onclose = () => {
    console.log('[WS] Metrics stream disconnected, reconnecting...');
    setTimeout(() => connectMetricsWS(onMessage), 3000);
  };
  return ws;
}
