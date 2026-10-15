import React from 'react';
import { Database, ShieldAlert, AlertTriangle, Flame, BrainCircuit } from 'lucide-react';

export function MetricsGrid({ stats }) {
  const processedEvents = stats?.processed_events ?? 0;
  const totalAlerts = stats?.total_alerts ?? 0;
  const openAlerts = stats?.open_alerts ?? 0;
  const highCritical = stats?.high_critical_alerts ?? 0;
  const mlAnomalies = stats?.ml_anomaly_count ?? 0;

  const cards = [
    {
      label: 'Processed Telemetry',
      value: processedEvents.toLocaleString(),
      subtext: 'Normalized security events',
      icon: Database,
      iconColor: 'text-cyan-400',
      iconBg: 'bg-cyan-500/10 border-cyan-500/20',
    },
    {
      label: 'Correlated Threats',
      value: totalAlerts.toLocaleString(),
      subtext: 'Deduplicated incident findings',
      icon: ShieldAlert,
      iconColor: 'text-blue-400',
      iconBg: 'bg-blue-500/10 border-blue-500/20',
    },
    {
      label: 'Open For Triage',
      value: openAlerts.toLocaleString(),
      subtext: 'Pending analyst resolution',
      icon: AlertTriangle,
      iconColor: 'text-amber-400',
      iconBg: 'bg-amber-500/10 border-amber-500/20',
    },
    {
      label: 'High & Critical',
      value: highCritical.toLocaleString(),
      subtext: 'Require urgent intervention',
      icon: Flame,
      iconColor: 'text-red-400',
      iconBg: 'bg-red-500/10 border-red-500/20',
    },
    {
      label: 'ML Anomalies',
      value: mlAnomalies.toLocaleString(),
      subtext: 'Isolation forest outliers',
      icon: BrainCircuit,
      iconColor: 'text-purple-400',
      iconBg: 'bg-purple-500/10 border-purple-500/20',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {cards.map((card, i) => {
        const Icon = card.icon;
        return (
          <div
            key={i}
            className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 transition-all hover:border-slate-700/80 hover:bg-slate-900/90 shadow-sm"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-medium text-slate-400">{card.label}</span>
              <div className={`p-2 rounded-lg border ${card.iconBg}`}>
                <Icon className={`w-4 h-4 ${card.iconColor}`} />
              </div>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100 tracking-tight mb-1">
              {card.value}
            </div>
            <div className="text-[11px] text-slate-500 truncate">{card.subtext}</div>
          </div>
        );
      })}
    </div>
  );
}
