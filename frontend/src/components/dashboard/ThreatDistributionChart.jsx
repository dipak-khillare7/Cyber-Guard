import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { getThreatColor, formatThreatLabel } from '../../utils/formatThreat';

const ThreatDistributionChart = ({ data = {} }) => {
  const chartData = Object.entries(data).map(([key, count]) => ({
    name: formatThreatLabel(key),
    rawKey: key,
    value: count,
    color: getThreatColor(key)
  }));

  if (chartData.length === 0) {
    return (
      <div className="table-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
        <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', fontWeight: 600 }}>Alert Threat Category Distribution</h3>
        <p className="empty-state">No categorized threats detected in database yet.</p>
      </div>
    );
  }

  return (
    <div className="table-card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
      <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', fontWeight: 600 }}>
        Alert Threat Category Distribution
      </h3>
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
