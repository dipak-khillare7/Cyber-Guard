import React, { useState, useEffect } from 'react';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import EmptyState from '../components/common/EmptyState';
import Pagination from '../components/common/Pagination';
import Modal from '../components/common/Modal';
import { authService } from '../services/authService';
import { formatDate } from '../utils/formatDate';
import { Shield, Filter, RefreshCw, Eye, UserCheck, Lock, Activity, ShieldAlert } from 'lucide-react';

const AuditLogs = () => {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [page, setPage] = useState(1);
  const [limit] = useState(15);
  const [actionFilter, setActionFilter] = useState('');
  const [usernameSearch, setUsernameSearch] = useState('');

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await authService.getAuditLogs({
        page,
        limit,
        action: actionFilter || undefined,
        username: usernameSearch || undefined
      });
      setLogs(res.items || []);
      setTotal(res.total || 0);
      setPages(res.pages || 1);
    } catch (err) {
      setError(err.message || 'Failed to retrieve system audit logs.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, actionFilter, usernameSearch]);

  const getActionBadgeColor = (action) => {
    if (action.includes('FAILURE')) return '#ef4444';
    if (action.includes('SUCCESS') || action.includes('CREATED')) return '#10b981';
    if (action.includes('UPDATED')) return '#f59e0b';
    return '#3b82f6';
  };

  return (
    <div className="audit-logs-page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Security Audit Trail Logs</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            Immutable chronological audit record of user authentication, state changes, and administrative security actions.
          </p>
        </div>
        <div>
          <button className="btn btn-secondary" onClick={fetchLogs} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> {loading ? 'Refreshing...' : 'Refresh Audit Trail'}
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="table-card" style={{ padding: '1rem 1.25rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: '1 1 200px' }}>
            <Filter size={14} color="var(--text-secondary)" />
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Action:</span>
            <select
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value);
                setPage(1);
              }}
              style={{
                width: '100%',
                backgroundColor: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem'
              }}
            >
              <option value="">All Action Types</option>
              <option value="LOGIN_SUCCESS">LOGIN_SUCCESS</option>
              <option value="LOGIN_FAILURE">LOGIN_FAILURE</option>
              <option value="LOGOUT">LOGOUT</option>
              <option value="ALERT_STATUS_UPDATED">ALERT_STATUS_UPDATED</option>
              <option value="INCIDENT_STATUS_UPDATED">INCIDENT_STATUS_UPDATED</option>
              <option value="RESPONSE_ACTION_TRIGGERED">RESPONSE_ACTION_TRIGGERED</option>
              <option value="EVENT_ANALYZED">EVENT_ANALYZED</option>
              <option value="USER_CREATED">USER_CREATED</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: '1 1 200px' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>User Search:</span>
            <input
              type="text"
              placeholder="Search by username..."
              value={usernameSearch}
              onChange={(e) => {
                setUsernameSearch(e.target.value);
                setPage(1);
              }}
              style={{
                width: '100%',
                backgroundColor: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem'
              }}
            />
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="table-card">
        {loading && (!logs || logs.length === 0) ? (
          <LoadingState message="Retrieving security audit logs..." />
        ) : error ? (
          <ErrorState message={error} onRetry={fetchLogs} />
        ) : logs.length === 0 ? (
          <EmptyState
            title="No Audit Logs Found"
            message="No system action logs match your query parameters."
            onAction={fetchLogs}
            actionLabel="Reset Search & Reload"
          />
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-card-header)', textAlign: 'left', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>ID</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Timestamp</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Action Code</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>User / Subject</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Resource</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Client IP</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Status</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Metadata</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <tr key={log.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>#{log.id}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{formatDate(log.timestamp)}</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          style={{
                            padding: '0.2rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            fontFamily: 'monospace',
                            fontWeight: 600,
                            color: getActionBadgeColor(log.action),
                            backgroundColor: `${getActionBadgeColor(log.action)}15`,
                            border: `1px solid ${getActionBadgeColor(log.action)}35`
                          }}
                        >
                          {log.action}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontWeight: 600, fontSize: '0.85rem' }}>
                        {log.username || 'Anonymous'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        {log.resource_type ? `${log.resource_type} #${log.resource_id}` : '-'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                        {log.ip_address || '127.0.0.1'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          style={{
                            fontSize: '0.75rem',
                            fontWeight: 600,
                            color: log.status === 'SUCCESS' ? '#10b981' : '#ef4444'
                          }}
                        >
                          ● {log.status}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <button
                          className="btn btn-secondary"
                          onClick={() => setSelectedLog(log)}
                          style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                        >
                          <Eye size={14} /> View Payload
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
              totalItems={total || logs.length}
              pageSize={limit}
            />
          </>
        )}
      </div>

      {/* Log Detail Modal */}
      {selectedLog && (
        <Modal title={`Audit Entry Details #${selectedLog.id}`} onClose={() => setSelectedLog(null)}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block' }}>Action</span>
              <strong style={{ fontSize: '0.9rem', color: getActionBadgeColor(selectedLog.action) }}>{selectedLog.action}</strong>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block' }}>User / Subject</span>
              <strong>{selectedLog.username || 'System / Anonymous'}</strong>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block' }}>Client IP Address</span>
              <span style={{ fontFamily: 'monospace' }}>{selectedLog.ip_address || '127.0.0.1'}</span>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block' }}>Timestamp</span>
              <span>{formatDate(selectedLog.timestamp)}</span>
            </div>
          </div>

          <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
            Audit Metadata JSON Payload
          </h4>
          <pre
            style={{
              backgroundColor: 'var(--bg-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              padding: '1rem',
              fontSize: '0.8rem',
              color: '#34d399',
              maxHeight: '200px',
              overflowY: 'auto'
            }}
          >
            {selectedLog.metadata_json ? JSON.stringify(JSON.parse(selectedLog.metadata_json), null, 2) : 'No extra metadata payload.'}
          </pre>
        </Modal>
      )}
    </div>
  );
};

export default AuditLogs;
