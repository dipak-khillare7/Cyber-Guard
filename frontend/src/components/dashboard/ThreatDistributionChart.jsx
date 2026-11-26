import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { getThreatDistributionChartData } from '../../utils/chartData';
import { getThreatColor } from '../../utils/formatThreat';

const ThreatDistributionChart = ({ data = {} }) => {
  const chartData = getThreatDistributionChartData(data)
    .map((entry) => ({ ...entry, color: getThreatColor(entry.rawKey) }));
  const hasInvalidCounts = !data
    || typeof data !== 'object'
    || Array.isArray(data)
    || Object.values(data).some((count) => !Number.isSafeInteger(count) || count < 0);

  if (chartData.length === 0) {
    return (
      <div className="table-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
        <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', fontWeight: 600 }}>Alert Threat Category Distribution</h3>
        <p className={hasInvalidCounts ? 'soc-inline-error' : 'empty-state'}>
          {hasInvalidCounts
            ? 'Threat category counts are invalid and cannot be displayed.'
            : 'No categorized alert records are available.'}
        </p>
      </div>
    );
  }

  return (
    <div className="table-card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
      <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', fontWeight: 600 }}>
        Alert Threat Category Distribution
      </h3>
      {hasInvalidCounts && <p className="soc-inline-error" role="status">Invalid category counts were omitted.</p>}
      <div style={{ width: '100%', height: 260 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={85}
              paddingAngle={4}
              dataKey="value"
            >
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f9fafb', borderRadius: '8px' }}
              formatter={(val, name) => [`${val} alerts`, name]}
            />
            <Legend
              verticalAlign="bottom"
              height={36}
              wrapperStyle={{ fontSize: '0.8rem', color: '#9ca3af' }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default ThreatDistributionChart;
