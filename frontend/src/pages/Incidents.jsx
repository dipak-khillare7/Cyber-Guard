import React, { useState } from 'react';
import IncidentDetailsModal from '../components/incidents/IncidentDetailsModal';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import EmptyState from '../components/common/EmptyState';
import RiskBadge from '../components/common/RiskBadge';
import StatusBadge from '../components/common/StatusBadge';
import Pagination from '../components/common/Pagination';
import { useIncidents } from '../hooks/useIncidents';
import { formatDate } from '../utils/formatDate';
import { formatThreatLabel } from '../utils/formatThreat';
import { ShieldAlert, RefreshCw, Eye, Filter } from 'lucide-react';

const Incidents = () => {
  const [page, setPage] = useState(1);
  const [limit] = useState(15);
  const [riskFilter, setRiskFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const { incidents, total, pages, loading, error, refresh } = useIncidents({
    page,
    limit,
    risk_level: riskFilter || undefined,
    status: statusFilter || undefined
  });

  const [selectedIncident, setSelectedIncident] = useState(null);

  return (
    <div className="incidents-page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Security Incident Management</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            High-severity threat cases, timeline investigation, and automated response oversight.
          </p>
        </div>
        <div>
          <button className="btn btn-secondary" onClick={refresh} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> {loading ? 'Refreshing...' : 'Refresh Incidents'}
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="table-card" style={{ padding: '1rem 1.25rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Filter size={14} color="var(--text-secondary)" />
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Risk Level:</span>
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
              <option value="HIGH">HIGH</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
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
              <option value="">All Incident Statuses</option>
              <option value="NEW">NEW</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Incidents Table */}
      <div className="table-card">
        {loading && (!incidents || incidents.length === 0) ? (
          <LoadingState message="Loading security incident cases..." />
        ) : error ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : incidents.length === 0 ? (
          <EmptyState
            title="No Incidents Reported"
            message="No active high-risk security incidents match your criteria."
            onAction={refresh}
            actionLabel="Reset Filters & Reload"
          />
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-card-header)', textAlign: 'left', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Incident ID</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Created At</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Threat Category</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Risk Level</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Status</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Last Updated</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((incident) => (
                    <tr key={incident.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>#{incident.id}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{formatDate(incident.created_at)}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', fontWeight: 600 }}>{formatThreatLabel(incident.threat_type || incident.title)}</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <RiskBadge level={incident.severity || incident.risk_level} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <StatusBadge status={incident.status} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{formatDate(incident.updated_at || incident.created_at)}</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <button
                          className="btn btn-secondary"
                          onClick={() => setSelectedIncident(incident)}
                          style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                        >
                          <Eye size={14} /> Case File & Timeline
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
              totalItems={total || incidents.length}
              pageSize={limit}
            />
          </>
        )}
      </div>

      {/* Incident Details & Timeline Modal */}
      {selectedIncident && (
        <IncidentDetailsModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onStatusUpdated={() => {
            refresh();
          }}
        />
      )}
    </div>
  );
};

export default Incidents;
