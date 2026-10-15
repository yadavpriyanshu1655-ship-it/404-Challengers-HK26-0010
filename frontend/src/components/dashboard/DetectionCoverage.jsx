import React from 'react';
import { CheckCircle2, Shield, BrainCircuit, ExternalLink } from 'lucide-react';
import { DETECTION_RULES } from '../../constants/threatConfig';

export function DetectionCoverage() {
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            Detection Capabilities & Coverage
          </h2>
          <p className="text-xs text-slate-400">Deterministic signature rules, behavioral baselines & ML</p>
        </div>
        <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-2 py-0.5 rounded">
          6 Active Pipelines
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {DETECTION_RULES.map((rule, idx) => (
          <div
            key={idx}
            className="p-3 bg-slate-950/40 border border-slate-800/80 rounded-lg flex flex-col justify-between hover:border-slate-700/60 transition-colors"
          >
            <div>
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="text-xs font-semibold text-slate-200 line-clamp-1">{rule.name}</span>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                    rule.type === 'Machine Learning'
                      ? 'bg-purple-950/80 text-purple-300 border border-purple-800/40'
                      : 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/40'
                  }`}
                >
                  {rule.type}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mb-2 font-mono">{rule.threshold}</p>
            </div>

            <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px]">
              <span className="text-slate-500 font-mono text-[10px] truncate max-w-[170px]">{rule.mitre}</span>
              <span className="flex items-center gap-1 text-emerald-400 text-[10px] font-medium">
                <CheckCircle2 className="w-3 h-3" />
                Active
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
