import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { SEVERITY_CONFIG } from '../../constants/threatConfig';

export function SeverityDistributionChart({ distribution = {} }) {
  const chartData = [
    { name: 'Critical', value: distribution.Critical || 0, color: SEVERITY_CONFIG.Critical.color },
    { name: 'High', value: distribution.High || 0, color: SEVERITY_CONFIG.High.color },
    { name: 'Medium', value: distribution.Medium || 0, color: SEVERITY_CONFIG.Medium.color },
    { name: 'Low', value: distribution.Low || 0, color: SEVERITY_CONFIG.Low.color },
  ].filter(item => item.value > 0);

  const total = chartData.reduce((acc, cur) => acc + cur.value, 0);

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 flex flex-col justify-between h-full">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Threat Severity Distribution</h2>
          <p className="text-xs text-slate-400">Classified by 4-tier risk assessment</p>
        </div>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
          {total} Total
        </span>
      </div>

      {total === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-slate-500 py-10">
          <p className="text-xs">No alerts classified yet.</p>
        </div>
      ) : (
        <div className="flex flex-col sm:flex-row items-center gap-4 flex-1">
          <div className="w-full sm:w-1/2 h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={65}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0];
                      return (
                        <div className="bg-slate-900 border border-slate-700 p-2 rounded-lg shadow-xl text-xs">
                          <span className="font-semibold text-slate-200">{data.name}: </span>
                          <span className="font-mono text-cyan-400 font-bold">{data.value}</span>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="w-full sm:w-1/2 space-y-2">
            {['Critical', 'High', 'Medium', 'Low'].map((tier) => {
              const count = distribution[tier] || 0;
              const config = SEVERITY_CONFIG[tier];
              const pct = total > 0 ? Math.round((count / total) * 100) : 0;
              return (
                <div key={tier} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${config.dot}`} />
                    <span className="text-slate-300 font-medium">{tier}</span>
                  </div>
                  <div className="flex items-center gap-2 font-mono">
                    <span className="text-slate-100 font-bold">{count}</span>
                    <span className="text-slate-500 text-[10px] w-8 text-right">{pct}%</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
