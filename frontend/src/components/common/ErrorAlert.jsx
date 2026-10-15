import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

export function ErrorAlert({ message = 'An error occurred while communicating with the telemetry API.', onRetry }) {
  return (
    <div className="flex items-start justify-between p-4 bg-red-950/40 border border-red-500/30 rounded-xl text-red-200 text-sm">
      <div className="flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 shrink-0" />
        <div>
          <strong className="font-semibold text-red-300 block mb-0.5">Telemetry Synchronization Error</strong>
          <p className="text-red-200/90 text-xs leading-relaxed">{message}</p>
        </div>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="inline-flex items-center gap-1.5 px-3 py-1 bg-red-900/60 hover:bg-red-800/60 text-red-200 rounded text-xs font-medium border border-red-700/50 transition-colors shrink-0"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Retry
        </button>
      )}
    </div>
  );
}
