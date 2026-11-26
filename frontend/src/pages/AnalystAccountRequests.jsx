import React, { useEffect, useState } from 'react';
import { Check, RefreshCw, X } from 'lucide-react';
import EmptyState from '../components/common/EmptyState';
import ErrorState from '../components/common/ErrorState';
import LoadingState from '../components/common/LoadingState';
import PageHeader from '../components/PageHeader';
import { authService } from '../services/authService';
import { formatDate } from '../utils/formatDate';

const STATUS_COLORS = {
  PENDING: '#f59e0b',
  APPROVED: '#10b981',
  REJECTED: '#ef4444',
};

const AnalystAccountRequests = () => {
  const [requests, setRequests] = useState([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState('PENDING');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [activeRequest, setActiveRequest] = useState(null);

  const loadRequests = async () => {
    try {
      setLoading(true);
      setError('');
      const result = await authService.getAnalystRequests({ status: statusFilter });
      setRequests(result.items || []);
      setTotal(result.total || 0);
    } catch (requestError) {
      setError(requestError.message || 'Unable to load Analyst account requests.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRequests();
  }, [statusFilter]);

  const reviewRequest = async (accountRequest, decision) => {
    const action = decision === 'approve' ? 'approve' : 'reject';
    const confirmation = decision === 'approve'
      ? `Approve ${accountRequest.full_name || accountRequest.email} as a SOC Analyst?`
      : `Reject the Analyst account request from ${accountRequest.full_name || accountRequest.email}?`;
    if (!window.confirm(confirmation)) return;

    setActiveRequest(accountRequest.id);
    setError('');
    setMessage('');
    try {
      if (action === 'approve') {
        await authService.approveAnalystRequest(accountRequest.id);
        setMessage(`${accountRequest.email} was approved as an Analyst.`);
      } else {
        await authService.rejectAnalystRequest(accountRequest.id);
        setMessage(`The request from ${accountRequest.email} was rejected.`);
      }
      await loadRequests();
    } catch (requestError) {
      setError(requestError.message || `Unable to ${action} this account request.`);
    } finally {
      setActiveRequest(null);
    }
  };

  return (
    <div className="analyst-account-requests-page">
      <PageHeader
        title="Analyst Account Requests"
        description="Review public SOC Analyst applications. Applicants must verify their email before approval."
      >
        <button
          type="button"
          className="btn btn-secondary"
          onClick={loadRequests}
          disabled={loading}
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
        >
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </PageHeader>

      <div className="table-card" style={{ padding: '1rem 1.25rem', margin: '1.5rem 0' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', maxWidth: '320px' }}>
          <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Request status</span>
          <select
            value={statusFilter}
            onChange={(event) => {
              setStatusFilter(event.target.value);
              setMessage('');
            }}
            style={{
              flex: 1,
              backgroundColor: 'var(--bg-secondary)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              padding: '0.45rem 0.75rem',
            }}
          >
            <option value="PENDING">Pending</option>
            <option value="APPROVED">Approved</option>
            <option value="REJECTED">Rejected</option>
          </select>
        </label>
      </div>

      {message && <p className="auth-notice auth-notice-success" role="status">{message}</p>}
      {error && <p className="auth-notice auth-notice-error" role="alert">{error}</p>}

      <div className="table-card">
        {loading && requests.length === 0 ? (
          <LoadingState message="Loading Analyst account requests..." />
        ) : error && requests.length === 0 ? (
          <ErrorState message={error} onRetry={loadRequests} />
        ) : requests.length === 0 ? (
          <EmptyState
            title={`No ${statusFilter.toLowerCase()} requests`}
            message="There are no Analyst account requests with this status."
            onAction={loadRequests}
            actionLabel="Refresh requests"
          />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ backgroundColor: 'var(--bg-card-header)', textAlign: 'left', borderBottom: '1px solid var(--border-color)' }}>
                  <th style={{ padding: '0.75rem 1rem' }}>Name</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Email</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Submitted</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Email verification</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Reviewed</th>
                  {statusFilter === 'PENDING' && <th style={{ padding: '0.75rem 1rem' }}>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {requests.map((accountRequest) => (
                  <tr key={accountRequest.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <td style={{ padding: '0.75rem 1rem' }}>{accountRequest.full_name || '-'}</td>
                    <td style={{ padding: '0.75rem 1rem' }}>{accountRequest.email}</td>
                    <td style={{ padding: '0.75rem 1rem' }}>{formatDate(accountRequest.created_at)}</td>
                    <td style={{ padding: '0.75rem 1rem' }}>{accountRequest.email_verified ? 'Verified' : 'Pending'}</td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span style={{
                        color: STATUS_COLORS[accountRequest.status],
                        fontWeight: 700,
                        fontSize: '0.8rem',
                      }}>
                        {accountRequest.status}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      {accountRequest.reviewed_at ? formatDate(accountRequest.reviewed_at) : '-'}
                    </td>
                    {statusFilter === 'PENDING' && (
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                          <button
                            type="button"
                            className="btn btn-primary"
                            onClick={() => reviewRequest(accountRequest, 'approve')}
                            disabled={activeRequest === accountRequest.id || !accountRequest.email_verified}
                            title={!accountRequest.email_verified ? 'Applicant must verify their email first.' : undefined}
                            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                          >
                            <Check size={14} /> Approve
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            onClick={() => reviewRequest(accountRequest, 'reject')}
                            disabled={activeRequest === accountRequest.id}
                            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                          >
                            <X size={14} /> Reject
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
            <p style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
              {total} request{total === 1 ? '' : 's'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AnalystAccountRequests;
