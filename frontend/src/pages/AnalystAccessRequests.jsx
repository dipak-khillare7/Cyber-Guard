import React, { useCallback, useEffect, useState } from 'react';
import { Check, RefreshCw, Shield, X } from 'lucide-react';
import ErrorState from '../components/common/ErrorState';
import LoadingState from '../components/common/LoadingState';
import { accessRequestService } from '../services/accessRequestService';
import { formatDate } from '../utils/formatDate';

const PAGE_SIZE = 20;

const AnalystAccessRequests = () => {
  const [requests, setRequests] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [activeRequestId, setActiveRequestId] = useState(null);

  const loadRequests = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const response = await accessRequestService.listPendingAnalystRequests({
        skip: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE,
      });
      const data = response.data?.data || response.data;
      setRequests(data.items || []);
      setTotal(data.total || 0);
    } catch (requestError) {
      setError(requestError.message || 'Could not load Analyst access requests.');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    loadRequests();
  }, [loadRequests]);

  const decide = async (accessRequest, decision) => {
    setActiveRequestId(accessRequest.id);
    setError('');
    setNotice('');
    try {
      await accessRequestService.decideAnalystRequest(accessRequest.id, decision);
      setTotal((current) => Math.max(0, current - 1));
      if (requests.length === 1 && page > 1) {
        setPage((current) => current - 1);
      } else {
        setRequests((current) => current.filter((item) => item.id !== accessRequest.id));
      }
      setNotice(
        decision === 'APPROVE'
          ? `Analyst access approved for ${accessRequest.username}.`
          : `Analyst access request rejected for ${accessRequest.username}.`,
      );
    } catch (requestError) {
      setError(requestError.message || 'Could not review the Analyst access request.');
    } finally {
      setActiveRequestId(null);
    }
  };

  return (
    <div className="user-portal-page analyst-access-admin">
      <header className="user-page-header">
        <div>
          <p className="user-eyebrow">ADMINISTRATION</p>
          <h1>Analyst access requests</h1>
          <p>Approving a request assigns the Analyst role. Rejection leaves the account unchanged.</p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={loadRequests} disabled={loading}>
          <RefreshCw size={16} aria-hidden="true" />
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </header>

      {notice && <p className="analyst-access-status" role="status">{notice}</p>}
      <p className="analyst-access-count">{total} pending request{total === 1 ? '' : 's'}</p>
      {error && !requests.length ? (
        <ErrorState message={error} onRetry={loadRequests} />
      ) : (
        <>
          {error && <p className="user-inline-error" role="alert">{error}</p>}
          <section className="user-portal-card analyst-access-requests-list" aria-label="Pending Analyst access requests">
            {loading && requests.length === 0 ? (
              <LoadingState message="Loading Analyst access requests…" />
            ) : requests.length === 0 ? (
              <p className="user-empty-inline">There are no pending Analyst access requests.</p>
            ) : (
              requests.map((item) => (
                <article className="analyst-access-admin-row" key={item.id}>
                  <div className="analyst-access-admin-identity">
                    <span className="dashboard-select-icon"><Shield size={20} aria-hidden="true" /></span>
                    <div>
                      <strong>{item.full_name || item.username}</strong>
                      <span>{item.email} · Requested {formatDate(item.requested_at)}</span>
                    </div>
                  </div>
                  <div className="analyst-access-admin-actions">
                    <button
                      className="btn btn-primary"
                      type="button"
                      onClick={() => decide(item, 'APPROVE')}
                      disabled={activeRequestId !== null}
                    >
                      <Check size={16} aria-hidden="true" />
                      {activeRequestId === item.id ? 'Saving…' : 'Approve and grant Analyst role'}
                    </button>
                    <button
                      className="btn btn-secondary"
                      type="button"
                      onClick={() => decide(item, 'REJECT')}
                      disabled={activeRequestId !== null}
                      aria-label={`Reject Analyst access request from ${item.username}`}
                    >
                      <X size={16} aria-hidden="true" /> Reject
                    </button>
                  </div>
                </article>
              ))
            )}
          </section>
          {total > PAGE_SIZE && (
            <nav className="user-pagination" aria-label="Analyst access request pages">
              <button
                className="btn btn-secondary"
                type="button"
                onClick={() => setPage((current) => Math.max(1, current - 1))}
                disabled={page === 1 || loading}
              >
                Previous
              </button>
              <span aria-live="polite">
                Page {page} of {Math.ceil(total / PAGE_SIZE)}
              </span>
              <button
                className="btn btn-secondary"
                type="button"
                onClick={() => setPage((current) => Math.min(Math.ceil(total / PAGE_SIZE), current + 1))}
                disabled={page >= Math.ceil(total / PAGE_SIZE) || loading}
              >
                Next
              </button>
            </nav>
          )}
        </>
      )}
    </div>
  );
};

export default AnalystAccessRequests;
