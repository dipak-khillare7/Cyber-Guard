import React, { useState } from 'react';
import AlertDetailsModal from '../components/alerts/AlertDetailsModal';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import EmptyState from '../components/common/EmptyState';
import RiskBadge from '../components/common/RiskBadge';
import StatusBadge from '../components/common/StatusBadge';
import Pagination from '../components/common/Pagination';
import { useAlerts } from '../hooks/useAlerts';
import { formatDate } from '../utils/formatDate';
import { formatThreatLabel } from '../utils/formatThreat';
import { formatConfidence } from '../utils/formatRisk';
import { AlertTriangle, RefreshCw, Eye, Filter } from 'lucide-react';

const Alerts = () => {
  const [page, setPage] = useState(1);
  const [limit] = useState(15);
  const [riskFilter, setRiskFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [threatFilter, setThreatFilter] = useState('');

  const { alerts, total, pages, loading, error, refresh } = useAlerts({
    page,
    limit,
    risk_level: riskFilter || undefined,
    status: statusFilter || undefined,
    threat_type: threatFilter || undefined
  });

  const [selectedAlert, setSelectedAlert] = useState(null);

  return (
    <div className="alerts-page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Threat Alerts Management</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            System-generated security alerts requiring triage, investigation, or resolution.
          </p>
        </div>
        <div>
          <button className="btn btn-secondary" onClick={refresh} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> {loading ? 'Refreshing...' : 'Refresh Alerts'}
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="table-card" style={{ padding: '1rem 1.25rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Filter size={14} color="var(--text-secondary)" />
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Risk:</span>
            <select
              value={riskFilter}
              onChange={(e) => {
                setRiskFilter(e.target.value);
                setPage(1);
              }}
              style={{
                backgroundColor: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem'
              }}
            >
              <option value="">All Risk Levels</option>
              <option value="LOW">LOW</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="HIGH">HIGH</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              style={{
                backgroundColor: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem'
              }}
            >
              <option value="">All Alert Statuses</option>
              <option value="NEW">NEW</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Threat:</span>
            <select
              value={threatFilter}
              onChange={(e) => {
                setThreatFilter(e.target.value);
                setPage(1);
              }}
              style={{
                backgroundColor: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem'
              }}
            >
              <option value="">All Threat Categories</option>
              <option value="BENIGN">BENIGN</option>
              <option value="DOS">DOS / DDOS</option>
              <option value="BRUTE_FORCE">BRUTE FORCE</option>
              <option value="WEB_ATTACK">WEB ATTACK</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Alerts Table */}
      <div className="table-card">
        {loading && (!alerts || alerts.length === 0) ? (
          <LoadingState message="Fetching security alerts from backend..." />
        ) : error ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : alerts.length === 0 ? (
          <EmptyState
            title="No Alerts Found"
            message="No security alerts match your selected filters."
            onAction={refresh}
            actionLabel="Reset Filters & Reload"
          />
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-card-header)', textAlign: 'left', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Alert ID</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Timestamp</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Threat Type</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Confidence</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Risk Score</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Risk Level</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Status</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert) => (
                    <tr key={alert.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>#{alert.id}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{formatDate(alert.created_at)}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', fontWeight: 600 }}>{formatThreatLabel(alert.threat_type)}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', fontFamily: 'monospace' }}>{formatConfidence(alert.confidence)}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', fontFamily: 'monospace' }}>{alert.risk_score ?? '-'}</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <RiskBadge level={alert.risk_level} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <StatusBadge status={alert.status} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <button
                          className="btn btn-secondary"
                          onClick={() => setSelectedAlert(alert)}
                          style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                        >
                          <Eye size={14} /> Review
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <Pagination
              currentPage={page}
              totalPages={pages || 1}
              onPageChange={(newPage) => setPage(newPage)}
              totalItems={total || alerts.length}
              pageSize={limit}
            />
          </>
        )}
      </div>

      {/* Alert Details & Status Update Modal */}
      {selectedAlert && (
        <AlertDetailsModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onStatusUpdated={() => {
            refresh();
          }}
        />
      )}
    </div>
  );
};

export default Alerts;
