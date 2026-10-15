import React from 'react';

export function CardSkeleton() {
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 animate-pulse">
      <div className="flex justify-between items-center mb-3">
        <div className="h-4 bg-slate-800 rounded w-24"></div>
        <div className="h-8 w-8 bg-slate-800 rounded-lg"></div>
      </div>
      <div className="h-8 bg-slate-800 rounded w-16 mb-2"></div>
      <div className="h-3 bg-slate-800 rounded w-32"></div>
    </div>
  );
}

export function TableSkeleton({ rows = 5 }) {
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 animate-pulse space-y-3">
      <div className="h-8 bg-slate-800 rounded w-full mb-4"></div>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-12 bg-slate-800/60 rounded w-full"></div>
      ))}
    </div>
  );
}

export function ChartSkeleton() {
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 animate-pulse h-72 flex flex-col justify-between">
      <div className="h-5 bg-slate-800 rounded w-36"></div>
      <div className="h-44 bg-slate-800/40 rounded w-full"></div>
    </div>
  );
}
