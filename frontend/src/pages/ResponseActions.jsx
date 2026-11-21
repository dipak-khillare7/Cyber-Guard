import React, { useState, useEffect } from 'react';
import ResponseDetailsModal from '../components/response/ResponseDetailsModal';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import EmptyState from '../components/common/EmptyState';
import Pagination from '../components/common/Pagination';
import { responseService } from '../services/responseService';
import { formatDate } from '../utils/formatDate';
import { PlayCircle, ShieldCheck, RefreshCw, Eye, Info } from 'lucide-react';

const ResponseActions = () => {
  const [responses, setResponses] = useState([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [page, setPage] = useState(1);
  const [limit] = useState(15);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [selectedResponse, setSelectedResponse] = useState(null);

  const fetchResponses = async () => {
    try {
      setLoading(true);
      setError(null);
      const skip = (page - 1) * limit;
      const res = await responseService.getResponses({ skip, limit });

      const payload = res?.data || res;
      const list = payload.items || payload.data?.items || (Array.isArray(payload) ? payload : []);
      const tot = payload.total ?? list.length;
      const pgs = payload.pages || Math.ceil(tot / limit) || 1;

      setResponses(list);
      setTotal(tot);
      setPages(pgs);
    } catch (err) {
      setError(err.response?.data?.error?.message || err.message || 'Failed to fetch simulated response actions log.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResponses();
  }, [page, limit]);

  return (
    <div className="response-actions-page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Simulated Response Actions</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            Automated countermeasures and mitigation actions executed in safe simulation mode.
          </p>
        </div>
        <div>
          <button className="btn btn-secondary" onClick={fetchResponses} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> {loading ? 'Refreshing...' : 'Refresh Log'}
          </button>
        </div>
      </div>

      {/* Safety Notice Banner */}
      <div
        style={{
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          border: '1px solid rgba(59, 130, 246, 0.3)',
          borderRadius: '8px',
          padding: '1rem 1.25rem',
          marginBottom: '1.5rem',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.75rem'
        }}
      >
        <Info size={20} color="#3b82f6" style={{ marginTop: '0.1rem', flexShrink: 0 }} />
        <div>
          <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, color: '#60a5fa' }}>
            Simulation Mode Enabled (Safe Operations)
          </h4>
          <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.85rem', color: '#93c5fd', lineHeight: 1.4 }}>
            All response actions listed below (e.g. SIMULATED_BLOCK, SIMULATED_ISOLATION, ESCALATE) are calculated by the AI engine and safely logged for evaluation. No real OS network interfaces or live firewall rules are altered.
          </p>
        </div>
      </div>

      {/* Main Table */}
      <div className="table-card">
        {loading && (!responses || responses.length === 0) ? (
          <LoadingState message="Fetching response action audit log..." />
        ) : error ? (
          <ErrorState message={error} onRetry={fetchResponses} />
        ) : responses.length === 0 ? (
          <EmptyState
            title="No Response Actions Executed"
            message="No simulated response actions have been triggered by the backend yet."
            onAction={fetchResponses}
            actionLabel="Reload Audit Log"
          />
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-card-header)', textAlign: 'left', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Action ID</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Timestamp</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Action Type</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Incident Ref</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Alert Ref</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Status</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Reason</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {responses.map((resp) => (
                    <tr key={resp.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>#{resp.id}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{formatDate(resp.executed_at || resp.created_at || resp.timestamp)}</td>
                      <td style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>
                        <span
                          style={{
                            padding: '0.2rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            fontFamily: 'monospace',
                            backgroundColor: resp.action_type?.includes('BLOCK') ? 'rgba(239, 68, 68, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                            color: resp.action_type?.includes('BLOCK') ? '#fca5a5' : '#93c5fd',
                            border: resp.action_type?.includes('BLOCK') ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(59, 130, 246, 0.4)'
                          }}
                        >
                          {resp.action_type}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                        {resp.incident_id ? `#${resp.incident_id}` : '-'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                        {resp.alert_id ? `#${resp.alert_id}` : '-'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.3rem',
                            fontSize: '0.75rem',
                            fontWeight: 600,
                            color: ['EXECUTED', 'COMPLETED', 'SUCCESS', 'SIMULATED'].includes(resp.status || resp.action_status) ? '#10b981' : '#f59e0b'
                          }}
                        >
                          <ShieldCheck size={14} />
                          {resp.status || resp.action_status || 'SIMULATED'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '220px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {resp.reason || resp.description || 'Automated policy rule match'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <button
                          className="btn btn-secondary"
                          onClick={() => setSelectedResponse(resp)}
                          style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                        >
                          <Eye size={14} /> Audit Detail
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
              totalItems={total || responses.length}
              pageSize={limit}
            />
          </>
        )}
      </div>

      {/* Response Audit Details Modal */}
      {selectedResponse && (
        <ResponseDetailsModal
          actionObj={selectedResponse}
          response={selectedResponse}
          onClose={() => setSelectedResponse(null)}
        />
      )}
    </div>
  );
};

export default ResponseActions;
