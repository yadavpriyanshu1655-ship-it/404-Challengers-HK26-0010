import React from 'react';
import { SEVERITY_CONFIG, STATUS_CONFIG } from '../../constants/threatConfig';

export function SeverityBadge({ severity }) {
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.Low;
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${config.badge}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      {config.label}
    </span>
  );
}

export function StatusBadge({ status }) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.Open;
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${config.badge}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      {config.label}
    </span>
  );
}

export function RiskScoreBadge({ score }) {
  let colorClasses = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
  if (score >= 85) {
    colorClasses = 'bg-red-500/15 text-red-400 border-red-500/30 shadow-sm shadow-red-500/20';
  } else if (score >= 65) {
    colorClasses = 'bg-orange-500/15 text-orange-400 border-orange-500/30';
  } else if (score >= 40) {
    colorClasses = 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold border ${colorClasses}`}>
      {score}/100
    </span>
  );
}

export function MitreBadge({ technique }) {
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800/40">
      {technique || 'T1110'}
    </span>
  );
}
