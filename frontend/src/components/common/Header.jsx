import React from 'react';
import { Shield, RefreshCw, Database, Trash2, Activity } from 'lucide-react';

export function Header({
  isLive,
  isRefreshing,
  onRefresh,
  onLoadSample,
  onReset,
}) {
  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-20">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-white font-black text-sm">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-bold text-base text-slate-100 tracking-tight flex items-center gap-1.5">
              CyberShield <span className="text-cyan-400 font-extrabold">AI</span>
            </h1>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
              ABCS-01
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Team 404 Challengers • Threat Intelligence & SOC</p>
        </div>
      </div>

      <div className="flex items-center gap-2.5">
        <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-slate-800/80 border border-slate-700/60 text-xs">
          <Activity className={`w-3.5 h-3.5 ${isLive ? 'text-emerald-400' : 'text-cyan-400'}`} />
          <span className="text-slate-300 font-medium">{isLive ? 'Connected: Localhost' : 'Synthetic Benchmark'}</span>
        </div>

        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-2 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors border border-transparent hover:border-slate-700"
          title="Refresh telemetry"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
        </button>

        <button
          onClick={onLoadSample}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded-lg text-xs font-semibold transition-colors"
        >
          <Database className="w-3.5 h-3.5" />
          Load Benchmark Sample
        </button>

        <button
          onClick={onReset}
          className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors border border-transparent hover:border-red-500/30"
          title="Clear events and alerts"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
}
