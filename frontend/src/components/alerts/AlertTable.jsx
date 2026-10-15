import React, { useState } from 'react';
import { Search, Filter, ChevronRight, ArrowUpDown, ChevronLeft, ShieldAlert } from 'lucide-react';
import { SeverityBadge, StatusBadge, RiskScoreBadge, MitreBadge } from '../common/Badge';

export function AlertTable({
  alerts = [],
  total = 0,
  onSelectAlert,
  severityFilter,
  onSeverityChange,
  statusFilter,
  onStatusChange,
  searchQuery,
  onSearchChange,
  onStatusUpdate,
}) {
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;

  const totalPages = Math.ceil(alerts.length / itemsPerPage) || 1;
  const paginatedAlerts = alerts.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const formatTimestamp = (ts) => {
    if (!ts) return '—';
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ' + d.toLocaleDateString();
    } catch {
      return ts;
    }
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
      {/* Table Header & Filter Bar */}
      <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between bg-slate-900/40">
        <div className="flex items-center gap-2 flex-1 max-w-md">
          <div className="relative w-full">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by IP, category, entity, or alert ID..."
              value={searchQuery}
              onChange={(e) => {
                onSearchChange(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950/80 border border-slate-700/80 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={severityFilter}
              onChange={(e) => {
                onSeverityChange(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-slate-950/80 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          <select
            value={statusFilter}
            onChange={(e) => {
              onStatusChange(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-950/80 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="All">All Statuses</option>
            <option value="Open">Open</option>
            <option value="Investigating">Investigating</option>
            <option value="Resolved">Resolved</option>
            <option value="Dismissed">Dismissed</option>
          </select>
        </div>
      </div>

      {/* Table Content */}
      <div className="overflow-x-auto flex-1">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/50 font-medium">
              <th className="py-3 px-4">Alert ID</th>
              <th className="py-3 px-4">Trigger Time</th>
              <th className="py-3 px-4">Threat Category</th>
              <th className="py-3 px-4">Target Entity</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Risk Score</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {paginatedAlerts.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500">
                  No threats match the specified search or filter criteria.
                </td>
              </tr>
            ) : (
              paginatedAlerts.map((alert) => (
                <tr
                  key={alert.id || alert.fingerprint}
                  onClick={() => onSelectAlert(alert)}
                  className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
                >
                  <td className="py-3 px-4 font-mono font-medium text-cyan-400">
                    {alert.alert_id || `CS-ALERT-${alert.id}`}
                  </td>
                  <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                    {formatTimestamp(alert.timestamp)}
                  </td>
                  <td className="py-3 px-4">
                    <span className="font-semibold text-slate-200 block line-clamp-1">{alert.category}</span>
                    <span className="text-[10px] text-slate-500 font-mono block">{alert.mitre_technique || 'T1110'}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="font-mono text-slate-300 font-medium">{alert.entity_value || alert.source_ip}</span>
                    <span className="text-[10px] text-slate-500 block capitalize">{alert.entity_type || 'source_ip'}</span>
                  </td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="py-3 px-4">
                    <RiskScoreBadge score={alert.risk_score} />
                  </td>
                  <td className="py-3 px-4">
                    <StatusBadge status={alert.status} />
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectAlert(alert);
                      }}
                      className="inline-flex items-center gap-1 text-slate-400 group-hover:text-cyan-400 font-medium transition-colors"
                    >
                      <span>Investigate</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 bg-slate-950/40">
        <div>
          Showing <span className="font-mono font-medium text-slate-200">{paginatedAlerts.length}</span> of{' '}
          <span className="font-mono font-medium text-slate-200">{alerts.length}</span> alerts
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
            disabled={currentPage === 1}
            className="p-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 transition-colors"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono text-xs text-slate-300">
            {currentPage} / {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
            disabled={currentPage === totalPages}
            className="p-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 transition-colors"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
