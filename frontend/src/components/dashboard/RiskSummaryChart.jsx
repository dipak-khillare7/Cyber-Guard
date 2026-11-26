import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { getRiskSummaryChartData } from '../../utils/chartData';
import { getRiskColor } from '../../utils/formatRisk';

const RiskSummaryChart = ({ data = {} }) => {
  const chartData = getRiskSummaryChartData(data)
    .map((entry) => ({ ...entry, color: getRiskColor(entry.rawLevel) }));
  const hasInvalidCounts = !data
    || typeof data !== 'object'
    || Array.isArray(data)
    || Object.values(data).some((count) => !Number.isSafeInteger(count) || count < 0);

  if (chartData.length === 0) {
    return (
      <div className="table-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
        <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', fontWeight: 600 }}>
          Alert Severity Distribution
        </h3>
        <p className={hasInvalidCounts ? 'soc-inline-error' : 'empty-state'}>
          {hasInvalidCounts
            ? 'Severity counts are invalid and cannot be displayed.'
            : 'No severity records are available.'}
        </p>
      </div>
    );
  }

  return (
    <div className="table-card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
      <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', fontWeight: 600 }}>
        Alert Severity Distribution
      </h3>
      {hasInvalidCounts && <p className="soc-inline-error" role="status">Invalid severity counts were omitted.</p>}
      <div style={{ width: '100%', height: 260 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
            <XAxis dataKey="level" stroke="#9ca3af" fontSize={12} tickLine={false} />
            <YAxis stroke="#9ca3af" fontSize={12} tickLine={false} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f9fafb', borderRadius: '8px' }}
              formatter={(val) => [`${val} alerts`, 'Count']}
            />
            <Bar dataKey="count" radius={[6, 6, 0, 0]}>
              {chartData.map((entry, index) => (
                <Cell key={`bar-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default RiskSummaryChart;
