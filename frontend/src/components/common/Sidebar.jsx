import React from 'react';
import { LayoutDashboard, ShieldAlert, ListFilter, Cpu, UploadCloud } from 'lucide-react';

export function Sidebar({ currentView, onViewChange, openAlertsCount = 0 }) {
  const navItems = [
    { id: 'dashboard', label: 'SOC Overview', icon: LayoutDashboard },
    { id: 'alerts', label: 'Threat Alerts', icon: ShieldAlert, badge: openAlertsCount },
    { id: 'events', label: 'Telemetry Logs', icon: ListFilter },
    { id: 'rules', label: 'Detection Engine', icon: Cpu },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-900/50 flex flex-col justify-between shrink-0 hidden lg:flex">
      <div className="p-4 space-y-6">
        <div>
          <span className="text-[10px] font-mono tracking-wider text-slate-500 uppercase px-3 block mb-2 font-semibold">
            Operations Center
          </span>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onViewChange(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="pt-4 border-t border-slate-800/60">
          <span className="text-[10px] font-mono tracking-wider text-slate-500 uppercase px-3 block mb-2 font-semibold">
            Detection Modules
          </span>
          <div className="px-3 py-2 bg-slate-950/60 border border-slate-800 rounded-lg text-xs space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Rule Engine:</span>
              <span className="text-emerald-400 font-mono text-[11px]">Active (5 Rules)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Isolation Forest:</span>
              <span className="text-purple-400 font-mono text-[11px]">Trained (v1.0)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Risk Scorer:</span>
              <span className="text-cyan-400 font-mono text-[11px]">4-Tier Matrix</span>
            </div>
          </div>
        </div>
      </div>

      <div className="p-4 border-t border-slate-800 text-slate-500 text-[11px]">
        <div className="flex items-center justify-between">
          <span>CyberShield Core</span>
          <span className="font-mono text-slate-400">v1.0.0</span>
        </div>
      </div>
    </aside>
  );
}
