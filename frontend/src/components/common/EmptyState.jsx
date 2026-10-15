import React from 'react';
import { ShieldAlert, Database } from 'lucide-react';

export function EmptyState({
  title = 'No threats detected',
  description = 'No security events or alerts match your current criteria.',
  icon: Icon = ShieldAlert,
  actionLabel,
  onAction,
}) {
  return (
    <div className="flex flex-col items-center justify-center py-12 px-4 text-center bg-slate-900/40 border border-slate-800/80 rounded-xl">
      <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700/50 flex items-center justify-center text-slate-400 mb-4">
        <Icon className="w-6 h-6 text-cyan-400" />
      </div>
      <h3 className="text-base font-semibold text-slate-200 mb-1">{title}</h3>
      <p className="text-sm text-slate-400 max-w-sm mb-5">{description}</p>
      {actionLabel && onAction && (
        <button
          onClick={onAction}
          className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-lg text-sm font-medium transition-colors"
        >
          <Database className="w-4 h-4" />
          {actionLabel}
        </button>
      )}
    </div>
  );
}
