import React from 'react';
import { Sparkles, Info } from 'lucide-react';
import { DATA_DISCLAIMER } from '../../data/syntheticBenchmark';

export function SyntheticBanner({ isLive = false }) {
  if (isLive) {
    return (
      <div className="flex items-center justify-between px-4 py-2 bg-emerald-950/30 border-b border-emerald-500/20 text-xs text-emerald-300">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-medium">Live Telemetry Pipeline Active</span>
          <span className="text-emerald-500/80">• Connected to SQLite backend at 127.0.0.1:8000</span>
        </div>
        <span className="font-mono text-[11px] text-emerald-400/80">API v1.0.0</span>
      </div>
    );
  }

  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between px-4 py-2.5 bg-cyan-950/40 border-b border-cyan-500/30 text-xs text-cyan-200 gap-2">
      <div className="flex items-center gap-2">
        <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
        <span className="font-semibold text-cyan-300">Synthetic Benchmark Mode (ABCS-01):</span>
        <span className="text-slate-300">{DATA_DISCLAIMER}</span>
      </div>
      <div className="flex items-center gap-1.5 text-cyan-400 text-[11px] shrink-0 font-medium bg-cyan-900/40 px-2 py-0.5 rounded border border-cyan-700/40">
        <Info className="w-3.5 h-3.5" />
        Sample Ground Truth
      </div>
    </div>
  );
}
