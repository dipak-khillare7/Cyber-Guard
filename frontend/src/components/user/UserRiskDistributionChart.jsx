import React from 'react';
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { Activity } from 'lucide-react';
import { getRiskColor } from '../../utils/formatRisk';

const UserRiskDistributionChart = ({ distribution }) => {
  const levels = [
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL',
    'INSUFFICIENT_INFORMATION',
    'ANALYSIS_UNAVAILABLE',
  ];
  const data = levels
    .map((level) => ({ level, count: distribution[level] || 0 }))
    .filter((entry) => entry.count > 0);
  const total = data.reduce((sum, entry) => sum + entry.count, 0);

  return (
    <section className="user-portal-card user-risk-chart" aria-labelledby="risk-chart-title">
      <div className="user-card-heading">
        <div>
        <h2 id="risk-chart-title">Website assessment results</h2>
        <p>Distribution of saved website analysis results.</p>
        </div>
        <span className="user-card-icon" aria-hidden="true">
          <Activity size={18} />
        </span>
      </div>
      {total === 0 ? (
        <p className="user-chart-empty" role="status">
          No website assessments have been recorded yet.
        </p>
      ) : (
        <div className="user-chart-container" role="img" aria-label={`${total} website assessments`}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="count"
                nameKey="level"
                innerRadius={58}
                outerRadius={94}
                paddingAngle={3}
                stroke="none"
              >
                {data.map((entry) => (
                  <Cell key={entry.level} fill={getRiskColor(entry.level)} />
                ))}
              </Pie>
              <Tooltip
                formatter={(value, name) => [`${value} assessments`, name]}
                contentStyle={{
                  backgroundColor: 'var(--bg-secondary)',
                  borderColor: 'var(--border-color)',
                  borderRadius: '8px',
                  color: 'var(--text-primary)',
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
      <div className="user-risk-legend">
        {levels.map((level) => (
          <div key={level} className="user-risk-legend-item">
            <span className="user-risk-dot" style={{ backgroundColor: getRiskColor(level) }} />
            <span>
              {level === 'INSUFFICIENT_INFORMATION'
              ? 'INSUFFICIENT'
              : level === 'ANALYSIS_UNAVAILABLE' ? 'UNAVAILABLE' : level}</span>
            <strong>{distribution[level] || 0}</strong>
          </div>
        ))}
      </div>
      <p className="user-chart-note">
        Missing evidence is not treated as proof that a website is safe.
      </p>
    </section>
  );
};

export default UserRiskDistributionChart;
