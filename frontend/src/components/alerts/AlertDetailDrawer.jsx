import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Clock,
  User,
  Network,
  Cpu,
  FileCheck2,
  LifeBuoy,
  CheckCircle,
  ExternalLink,
} from 'lucide-react';
import { SeverityBadge, StatusBadge, RiskScoreBadge, MitreBadge } from '../common/Badge';

export function AlertDetailDrawer({ alert, onClose, onUpdateStatus }) {
  if (!alert) return null;

  const [currentStatus, setCurrentStatus] = useState(alert.status || 'Open');
  const [isUpdating, setIsUpdating] = useState(false);

  const handleStatusChange = async (newStatus) => {
    setIsUpdating(true);
    setCurrentStatus(newStatus);
    await onUpdateStatus(alert.id, newStatus);
    setIsUpdating(false);
  };

  const evidenceList = Array.isArray(alert.evidence)
    ? alert.evidence
    : typeof alert.evidence === 'string'
    ? alert.evidence.split('\n').filter(Boolean)
    : [String(alert.evidence || '')];

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end">
      <div
        className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto shadow-2xl flex flex-col justify-between"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div>
          <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-950/40">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="font-mono text-xs font-bold text-cyan-400">
                  {alert.alert_id || `CS-ALERT-${alert.id}`}
                </span>
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={currentStatus} />
              </div>
              <h2 className="text-lg font-bold text-slate-100 tracking-tight leading-snug">
                {alert.category}
              </h2>
            </div>
            <button
              onClick={onClose}
              aria-label="Close incident drawer"
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Incident Scoring Metrics Banner */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-4 bg-slate-950/60 border-b border-slate-800/80 text-xs">
            <div className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block mb-1">Composite Risk</span>
              <RiskScoreBadge score={alert.risk_score} />
            </div>
            <div className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block mb-1">Confidence</span>
              <span className="font-mono text-slate-200 font-bold">
                {Math.round((alert.confidence ?? 0.85) * 100)}%
              </span>
            </div>
            <div className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block mb-1">ML Outlier Score</span>
              <span className="font-mono text-purple-400 font-bold">
                {alert.anomaly_score !== null && alert.anomaly_score !== undefined
                  ? alert.anomaly_score.toFixed(2)
                  : 'N/A'}
              </span>
            </div>
            <div className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block mb-1">Confirmation</span>
              <span
                className={`text-[11px] font-semibold ${
                  alert.is_confirmed !== false ? 'text-emerald-400' : 'text-amber-400'
                }`}
              >
                {alert.is_confirmed !== false ? 'Corroborated' : 'Unconfirmed'}
              </span>
            </div>
          </div>

          {/* Drawer Body */}
          <div className="p-6 space-y-6 text-sm">
            {/* Description Narrative */}
            <div>
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <FileCheck2 className="w-4 h-4 text-cyan-400" />
                Incident Narrative & Context
              </h3>
              <p className="text-slate-300 text-xs leading-relaxed bg-slate-950/40 p-3.5 rounded-lg border border-slate-800/80">
                {alert.description || 'No detailed narrative provided for this incident.'}
              </p>
            </div>

            {/* Entity & Temporal Context */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-slate-950/40 border border-slate-800 rounded-lg space-y-2">
                <div className="flex items-center gap-2 text-slate-400">
                  <Network className="w-4 h-4 text-cyan-400" />
                  <span className="font-medium text-slate-300">Target Entity:</span>
                </div>
                <div className="font-mono text-slate-100 font-bold pl-6">
                  {alert.entity_value || alert.source_ip}
                  <span className="text-[10px] text-slate-500 block font-normal capitalize">
                    {alert.entity_type || 'source_ip'}
                  </span>
                </div>
              </div>

              <div className="p-3 bg-slate-950/40 border border-slate-800 rounded-lg space-y-2">
                <div className="flex items-center gap-2 text-slate-400">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  <span className="font-medium text-slate-300">Timestamp:</span>
                </div>
                <div className="font-mono text-slate-100 pl-6 text-xs">{alert.timestamp}</div>
              </div>
            </div>

            {/* MITRE ATT&CK Mapping */}
            <div>
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-cyan-400" />
                MITRE ATT&CK Mapping
              </h3>
              <div className="flex items-center gap-2">
                <MitreBadge technique={alert.mitre_technique || 'T1110.001 - Brute Force'} />
                <span className="text-xs text-slate-400">Tactics: Credential Access, Defense Evasion</span>
              </div>
            </div>

            {/* Supporting Evidence Breakdown */}
            <div>
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                Supporting Telemetry Evidence
              </h3>
              <ul className="space-y-2 bg-slate-950/40 p-3.5 rounded-lg border border-slate-800/80">
                {evidenceList.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-2.5 text-xs text-slate-300">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                    <span className="leading-relaxed">{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Safe Defensive Recommendations */}
            <div>
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <LifeBuoy className="w-4 h-4 text-emerald-400" />
                Recommended SOC Defensive Steps
              </h3>
              <div className="bg-emerald-950/20 border border-emerald-500/30 p-3.5 rounded-lg text-xs text-emerald-200/90 leading-relaxed">
                {alert.recommendation || 'Follow organizational standard incident response procedures.'}
              </div>
            </div>
          </div>
        </div>

        {/* Drawer Footer & Triage Controls */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/70 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-medium">Triage Status:</span>
            <select
              value={currentStatus}
              onChange={(e) => handleStatusChange(e.target.value)}
              disabled={isUpdating}
              className="bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
            >
              <option value="Open">Open</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
              <option value="Dismissed">Dismissed</option>
            </select>
            {isUpdating && <span className="text-[11px] text-cyan-400 animate-pulse">Saving...</span>}
          </div>

          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
