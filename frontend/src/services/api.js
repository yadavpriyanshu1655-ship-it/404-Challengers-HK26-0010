/**
 * CyberShield AI — Frontend API Service Client
 * Connects to FastAPI REST backend with graceful fallback to labeled synthetic benchmark telemetry.
 */

import {
  SYNTHETIC_DASHBOARD_STATS,
  SYNTHETIC_ALERTS,
  SYNTHETIC_EVENTS,
} from '../data/syntheticBenchmark';

const API_BASE = '/api';

/**
 * Health check endpoint
 */
export async function fetchHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { data: await res.json(), isLive: true };
  } catch (err) {
    return {
      data: { status: 'offline', service: 'CyberShield AI', database: 'synthetic-cache' },
      isLive: false,
      error: err.message,
    };
  }
}

/**
 * Fetch executive dashboard summary metrics
 */
export async function fetchDashboardStats() {
  try {
    const res = await fetch(`${API_BASE}/dashboard/stats`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    return { data, isLive: true };
  } catch (err) {
    return { data: SYNTHETIC_DASHBOARD_STATS, isLive: false, error: err.message };
  }
}

/**
 * Fetch paginated alerts with filters
 */
export async function fetchAlerts({ severity = '', status = '', search = '', limit = 100, offset = 0 } = {}) {
  try {
    const params = new URLSearchParams();
    if (severity && severity !== 'All') params.set('severity', severity);
    if (status && status !== 'All') params.set('status', status);
    if (search) params.set('search', search);
    params.set('limit', limit.toString());
    params.set('offset', offset.toString());

    const res = await fetch(`${API_BASE}/alerts?${params.toString()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    return { data: data.alerts || [], total: data.total ?? data.alerts?.length ?? 0, isLive: true };
  } catch (err) {
    // Filter local synthetic fallback
    let filtered = [...SYNTHETIC_ALERTS];
    if (severity && severity !== 'All') {
      filtered = filtered.filter(a => a.severity.toLowerCase() === severity.toLowerCase());
    }
    if (status && status !== 'All') {
      filtered = filtered.filter(a => a.status.toLowerCase() === status.toLowerCase());
    }
    if (search) {
      const q = search.toLowerCase();
      filtered = filtered.filter(a =>
        a.category.toLowerCase().includes(q) ||
        a.source_ip.toLowerCase().includes(q) ||
        a.alert_id?.toLowerCase().includes(q) ||
        a.description?.toLowerCase().includes(q)
      );
    }
    return { data: filtered, total: filtered.length, isLive: false, error: err.message };
  }
}

/**
 * Fetch alert details by ID
 */
export async function fetchAlertDetail(id) {
  try {
    const res = await fetch(`${API_BASE}/alerts/${id}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { data: await res.json(), isLive: true };
  } catch (err) {
    const found = SYNTHETIC_ALERTS.find(a => a.id === Number(id));
    return { data: found || null, isLive: false, error: err.message };
  }
}

/**
 * Update alert triage status
 */
export async function updateAlertStatus(id, newStatus) {
  try {
    const res = await fetch(`${API_BASE}/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { success: true, isLive: true };
  } catch (err) {
    // Update local synthetic object if in offline mode
    const item = SYNTHETIC_ALERTS.find(a => a.id === Number(id));
    if (item) item.status = newStatus;
    return { success: true, isLive: false, note: 'Updated local synthetic state' };
  }
}

/**
 * Fetch paginated security telemetry events
 */
export async function fetchEvents({ limit = 50, offset = 0, status = '', search = '' } = {}) {
  try {
    const params = new URLSearchParams();
    params.set('limit', limit.toString());
    params.set('offset', offset.toString());
    if (status && status !== 'All') params.set('status', status);
    if (search) params.set('search', search);

    const res = await fetch(`${API_BASE}/events?${params.toString()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    return { data: data.events || [], total: data.total ?? data.events?.length ?? 0, isLive: true };
  } catch (err) {
    let filtered = [...SYNTHETIC_EVENTS];
    if (status && status !== 'All') {
      filtered = filtered.filter(e => e.status.toLowerCase() === status.toLowerCase());
    }
    if (search) {
      const q = search.toLowerCase();
      filtered = filtered.filter(e =>
        e.username.toLowerCase().includes(q) ||
        e.source_ip.toLowerCase().includes(q) ||
        e.resource.toLowerCase().includes(q)
      );
    }
    return { data: filtered, total: filtered.length, isLive: false, error: err.message };
  }
}

/**
 * Trigger synthetic sample pipeline
 */
export async function triggerSampleData() {
  try {
    const res = await fetch(`${API_BASE}/demo/sample`, { method: 'POST' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { data: await res.json(), isLive: true };
  } catch (err) {
    return { data: { message: 'Loaded offline synthetic benchmark' }, isLive: false };
  }
}

/**
 * Reset demo data
 */
export async function triggerResetData() {
  try {
    const res = await fetch(`${API_BASE}/demo/reset`, { method: 'POST' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { data: await res.json(), isLive: true };
  } catch (err) {
    return { data: { message: 'Reset local state' }, isLive: false };
  }
}

/**
 * Upload CSV telemetry logs
 */
export async function uploadLogFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/logs/upload`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
    throw new Error(err.detail?.message || err.detail || 'Upload failed');
  }
  return await res.json();
}
