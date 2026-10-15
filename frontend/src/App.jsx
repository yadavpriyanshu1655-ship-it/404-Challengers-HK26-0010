import React, { useState, useEffect } from 'react';
import {
  fetchHealth,
  fetchDashboardStats,
  fetchAlerts,
  fetchEvents,
  updateAlertStatus,
  triggerSampleData,
  triggerResetData,
} from './services/api';

import { Header } from './components/common/Header';
import { Sidebar } from './components/common/Sidebar';
import { SyntheticBanner } from './components/common/SyntheticBanner';
import { ErrorAlert } from './components/common/ErrorAlert';
import { CardSkeleton, TableSkeleton } from './components/common/LoadingSkeleton';
import { EmptyState } from './components/common/EmptyState';
import { LogUploadModal } from './components/ingestion/LogUploadModal';

import { MetricsGrid } from './components/dashboard/MetricsGrid';
import { SeverityDistributionChart } from './components/dashboard/SeverityDistributionChart';
import { ActivityTrendChart } from './components/dashboard/ActivityTrendChart';
import { DetectionCoverage } from './components/dashboard/DetectionCoverage';

import { AlertTable } from './components/alerts/AlertTable';
import { AlertDetailDrawer } from './components/alerts/AlertDetailDrawer';

import { EventTable } from './components/events/EventTable';
import { EventDetailModal } from './components/events/EventDetailModal';

import { ShieldCheck, ShieldAlert, Cpu, Database } from 'lucide-react';

export default function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [isLive, setIsLive] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [isUploadOpen, setIsUploadOpen] = useState(false);

  // Core telemetry state
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);

  // Selected item inspection state
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Filters
  const [alertSeverity, setAlertSeverity] = useState('All');
  const [alertStatus, setAlertStatus] = useState('All');
  const [alertSearch, setAlertSearch] = useState('');

  const [eventStatus, setEventStatus] = useState('All');
  const [eventSearch, setEventSearch] = useState('');

  const loadData = async (showLoading = true) => {
    if (showLoading) setIsLoading(true);
    setIsRefreshing(true);
    setError(null);

    try {
      const healthRes = await fetchHealth();
      setIsLive(healthRes.isLive);

      const [statsRes, alertsRes, eventsRes] = await Promise.all([
        fetchDashboardStats(),
        fetchAlerts({ severity: alertSeverity, status: alertStatus, search: alertSearch }),
        fetchEvents({ status: eventStatus, search: eventSearch }),
      ]);

      setStats(statsRes.data);
      setAlerts(alertsRes.data || []);
      setEvents(eventsRes.data || []);
    } catch (err) {
      setError(err.message || 'Failed to communicate with the security telemetry pipeline.');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData(true);
  }, [alertSeverity, alertStatus, alertSearch, eventStatus, eventSearch]);

  const handleUpdateStatus = async (alertId, newStatus) => {
    await updateAlertStatus(alertId, newStatus);
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
    );
    if (selectedAlert && selectedAlert.id === alertId) {
      setSelectedAlert((prev) => ({ ...prev, status: newStatus }));
    }
    // Refresh stats in background
    fetchDashboardStats().then((res) => setStats(res.data));
  };

  const handleLoadSample = async () => {
    setIsRefreshing(true);
    await triggerSampleData();
    await loadData(false);
  };

  const handleReset = async () => {
    setIsRefreshing(true);
    await triggerResetData();
    await loadData(false);
  };

  const openAlertsCount = stats?.open_alerts ?? alerts.filter((a) => a.status === 'Open').length;

  return (
    <div className="min-h-screen flex flex-col bg-[#0a0f1d] text-slate-100">
      {/* Disclaimer Banner */}
      <SyntheticBanner isLive={isLive} />

      {/* Main Top Header */}
      <Header
        isLive={isLive}
        isRefreshing={isRefreshing}
        onRefresh={() => loadData(false)}
        onOpenUpload={() => setIsUploadOpen(true)}
        onLoadSample={handleLoadSample}
        onReset={handleReset}
      />

      {/* App Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar
          currentView={currentView}
          onViewChange={setCurrentView}
          openAlertsCount={openAlertsCount}
          onOpenUpload={() => setIsUploadOpen(true)}
        />

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 space-y-6">
          {error && <ErrorAlert message={error} onRetry={() => loadData(true)} />}

          {isLoading ? (
            <div className="space-y-6">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                {[...Array(5)].map((_, i) => (
                  <CardSkeleton key={i} />
                ))}
              </div>
              <TableSkeleton rows={6} />
            </div>
          ) : (
            <>
              {/* VIEW: DASHBOARD OVERVIEW */}
              {currentView === 'dashboard' && (
                <div className="space-y-6">
                  {/* Overview Metrics Cards */}
                  <MetricsGrid stats={stats} />

                  {/* Charts Grid */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <SeverityDistributionChart distribution={stats?.severity_distribution} />
                    <ActivityTrendChart trend={stats?.event_trend} />
                  </div>

                  {/* Threat Alert Preview */}
                  <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-cyan-400" />
                          Recent Correlated Findings
                        </h2>
                        <p className="text-xs text-slate-400">High priority detections requiring attention</p>
                      </div>
                      <button
                        onClick={() => setCurrentView('alerts')}
                        className="text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors"
                      >
                        View all {alerts.length} alerts →
                      </button>
                    </div>

                    <AlertTable
                      alerts={alerts.slice(0, 5)}
                      total={alerts.length}
                      onSelectAlert={setSelectedAlert}
                      severityFilter={alertSeverity}
                      onSeverityChange={setAlertSeverity}
                      statusFilter={alertStatus}
                      onStatusChange={setAlertStatus}
                      searchQuery={alertSearch}
                      onSearchChange={setAlertSearch}
                      onStatusUpdate={handleUpdateStatus}
                    />
                  </div>

                  {/* Detection Coverage Matrix */}
                  <DetectionCoverage />
                </div>
              )}

              {/* VIEW: THREAT ALERTS */}
              {currentView === 'alerts' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-bold text-slate-100">Threat Alerts & Incidents</h2>
                      <p className="text-xs text-slate-400">
                        Multi-factor risk assessment, evidence analysis, and triage management
                      </p>
                    </div>
                  </div>

                  {alerts.length === 0 ? (
                    <EmptyState
                      title="No threat alerts found"
                      description="No alerts match the active filters. You can load synthetic sample benchmark logs to evaluate detections."
                      actionLabel="Load Benchmark Telemetry"
                      onAction={handleLoadSample}
                    />
                  ) : (
                    <AlertTable
                      alerts={alerts}
                      total={alerts.length}
                      onSelectAlert={setSelectedAlert}
                      severityFilter={alertSeverity}
                      onSeverityChange={setAlertSeverity}
                      statusFilter={alertStatus}
                      onStatusChange={setAlertStatus}
                      searchQuery={alertSearch}
                      onSearchChange={setAlertSearch}
                      onStatusUpdate={handleUpdateStatus}
                    />
                  )}
                </div>
              )}

              {/* VIEW: TELEMETRY EVENTS */}
              {currentView === 'events' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-bold text-slate-100">Telemetry Logs Explorer</h2>
                      <p className="text-xs text-slate-400">
                        Normalized security event records, authentication outcome, and resource targets
                      </p>
                    </div>
                  </div>

                  {events.length === 0 ? (
                    <EmptyState
                      title="No telemetry events found"
                      description="No event records match the search filter. Load sample data to inspect logs."
                      actionLabel="Load Sample Telemetry"
                      onAction={handleLoadSample}
                    />
                  ) : (
                    <EventTable
                      events={events}
                      total={events.length}
                      onSelectEvent={setSelectedEvent}
                      searchQuery={eventSearch}
                      onSearchChange={setEventSearch}
                      statusFilter={eventStatus}
                      onStatusChange={setEventStatus}
                    />
                  )}
                </div>
              )}

              {/* VIEW: DETECTION RULES */}
              {currentView === 'rules' && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-base font-bold text-slate-100">Detection Rules & Governance Engine</h2>
                    <p className="text-xs text-slate-400">
                      Explainable threat detection logic, behavioral baseline configurations, and MITRE mapping
                    </p>
                  </div>
                  <DetectionCoverage />
                </div>
              )}
            </>
          )}
        </main>
      </div>

      {/* Slide-over Incident Detail Drawer */}
      {selectedAlert && (
        <AlertDetailDrawer
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onUpdateStatus={handleUpdateStatus}
        />
      )}

      {/* Raw Event Detail Modal */}
      {selectedEvent && (
        <EventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

      {/* Security Log Ingestion Modal */}
      <LogUploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={() => loadData(false)}
      />
    </div>
  );
}
