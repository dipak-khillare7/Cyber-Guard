import React from 'react';
import PageHeader from '../components/PageHeader';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import StatusBadge from '../components/StatusBadge';
import { useFetch } from '../hooks/useFetch';
import { statisticService } from '../services/api';
import { BarChart3, PieChart } from 'lucide-react';

const Analytics = () => {
  const { data: stats, loading, error, refetch } = useFetch(statisticService.getStatistics);

  if (loading) return <LoadingState message="Calculating security analytics breakdown..." />;
  if (error) return <ErrorState message={error} onRetry={refetch} />;

  const threatTypeEntries = Object.entries(stats?.threats_by_type || {});
  const severityEntries = Object.entries(stats?.threats_by_severity || {});

  return (
    <div>
      <PageHeader
        title="Threat Statistics & Analytics"
        description="Empirical distribution of detected threat categories and risk severity breakdown."
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
        {/* Threats by Category */}
        <div className="table-card" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <BarChart3 size={20} style={{ color: 'var(--accent-cyan)' }} />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Threats by Category</h3>
          </div>
          {threatTypeEntries.length === 0 ? (
            <div className="empty-state">No categorized threats detected yet.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {threatTypeEntries.map(([category, count]) => (
                <div key={category} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
                  <span style={{ fontWeight: 500 }}>{category}</span>
                  <span className="font-mono" style={{ padding: '0.2rem 0.6rem', backgroundColor: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)' }}>
                    {count}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Threats by Severity */}
        <div className="table-card" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <PieChart size={20} style={{ color: 'var(--accent-purple)' }} />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Threats by Risk Severity</h3>
          </div>
          {severityEntries.length === 0 ? (
            <div className="empty-state">No severity risk records available.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {severityEntries.map(([level, count]) => (
                <div key={level} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
                  <StatusBadge level={level} />
                  <span className="font-mono" style={{ padding: '0.2rem 0.6rem', backgroundColor: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)' }}>
                    {count}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Analytics;
