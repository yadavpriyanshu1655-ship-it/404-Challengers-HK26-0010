import React from 'react';
import { X, FileCode, CheckCircle2 } from 'lucide-react';

export function EventDetailModal({ event, onClose }) {
  if (!event) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div
        className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100">Telemetry Event #{event.id}</h3>
          </div>
          <button
            onClick={onClose}
            aria-label="Close event details modal"
            className="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 space-y-3 text-xs">
          <div className="grid grid-cols-2 gap-2">
            <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block">Timestamp</span>
              <span className="font-mono text-slate-200">{event.timestamp}</span>
            </div>
            <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block">Status</span>
              <span className="font-semibold text-slate-200 capitalize">{event.status}</span>
            </div>
            <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block">Source IP</span>
              <span className="font-mono text-cyan-400">{event.source_ip}</span>
            </div>
            <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block">Username</span>
              <span className="font-semibold text-slate-200">{event.username}</span>
            </div>
            <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block">Event Action</span>
              <span className="font-mono text-slate-300">{event.event_type}</span>
            </div>
            <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block">Payload Size</span>
              <span className="font-mono text-slate-300">{event.payload_size || 0} bytes</span>
            </div>
          </div>

          <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
            <span className="text-slate-500 text-[10px] uppercase font-mono block mb-1">Resource Path</span>
            <span className="font-mono text-slate-300 break-all">{event.resource}</span>
          </div>

          {event.fingerprint && (
            <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-mono block mb-1">
                Deduplication Fingerprint
              </span>
              <span className="font-mono text-[10px] text-slate-400 break-all select-all">
                {event.fingerprint}
              </span>
            </div>
          )}
        </div>

        <div className="p-3 border-t border-slate-800 bg-slate-950/40 flex justify-end">
          <button
            onClick={onClose}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
