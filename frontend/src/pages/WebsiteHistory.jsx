import React, { useCallback, useEffect, useState } from 'react';
import { Database, Search } from 'lucide-react';
import ErrorState from '../components/common/ErrorState';
import LoadingState from '../components/common/LoadingState';
import Modal from '../components/common/Modal';
import WebsiteAssessmentDetails from '../components/user/WebsiteAssessmentDetails';
import WebsiteRiskBadge from '../components/user/WebsiteRiskBadge';
import { websiteAssessmentService } from '../services/websiteAssessmentService';
import { formatDate } from '../utils/formatDate';

const PAGE_SIZE = 15;

const WebsiteHistory = () => {
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [riskLevel, setRiskLevel] = useState('');
  const [sortOrder, setSortOrder] = useState('newest');
  const [page, setPage] = useState(1);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedAssessment, setSelectedAssessment] = useState(null);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const refresh = useCallback(() => setRefreshVersion((value) => value + 1), []);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search.trim()), 250);
    return () => clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    websiteAssessmentService.getAssessments({
      skip: (page - 1) * PAGE_SIZE,
      limit: PAGE_SIZE,
      search: debouncedSearch || undefined,
      risk_level: riskLevel || undefined,
      sort_order: sortOrder,
    })
      .then((response) => {
        if (active) setData(response.data?.data || response.data);
      })
      .catch((requestError) => {
        if (active) setError(requestError.message || 'Could not load your website assessment history.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [page, debouncedSearch, riskLevel, sortOrder, refreshVersion]);

  const records = data?.items || [];
  const total = data?.total || 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  if (loading && !data) {
    return <LoadingState message="Loading your website history…" />;
  }
  if (error && !data) {
    return <ErrorState message={error} onRetry={refresh} />;
  }

  return (
    <div className="user-portal-page">
      <header className="user-page-header">
        <div>
          <p className="user-eyebrow">YOUR SAVED CHECKS</p>
          <h1>Website history</h1>
          <p>Search, filter, and review website security assessments linked to your account.</p>
        </div>
        <span className="user-history-count">{total} matching checks</span>
      </header>

      {error && <p className="user-inline-error" role="status">{error}</p>}

      <section className="user-portal-card user-history-filters" aria-label="Filter website history">
        <div className="user-search-field">
          <Search size={17} aria-hidden="true" />
          <label className="sr-only" htmlFor="website-history-search">Search website history</label>
          <input
            id="website-history-search"
            type="search"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
            placeholder="Search domain"
          />
        </div>
        <div className="user-filter-controls">
          <div className="user-filter-field">
            <label htmlFor="website-risk-filter">Risk indicator</label>
            <select
              id="website-risk-filter"
              value={riskLevel}
              onChange={(event) => {
                setRiskLevel(event.target.value);
                setPage(1);
              }}
            >
              <option value="">All results</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
              <option value="INSUFFICIENT_INFORMATION">Insufficient information</option>
              <option value="ANALYSIS_UNAVAILABLE">Analysis unavailable</option>
            </select>
          </div>
          <div className="user-filter-field">
            <label htmlFor="website-history-sort">Date order</label>
            <select
              id="website-history-sort"
              value={sortOrder}
              onChange={(event) => {
                setSortOrder(event.target.value);
                setPage(1);
              }}
            >
              <option value="newest">Newest first</option>
              <option value="oldest">Oldest first</option>
            </select>
          </div>
        </div>
      </section>

      <section className="user-portal-card user-history-card">
        {loading ? (
          <LoadingState message="Updating website history…" />
        ) : records.length === 0 ? (
          <div className="user-empty-history">
            <Database size={30} aria-hidden="true" />
            <h2>{total ? 'No matching checks' : 'No website checks yet'}</h2>
            <p>{total
              ? 'Try another search or risk filter.'
              : 'Website checks you submit will appear here.'}
            </p>
          </div>
        ) : (
          <>
            <div className="user-table-wrap">
              <table className="data-table user-history-table website-history-table">
                <caption className="sr-only">Your website assessment history</caption>
                <thead>
                  <tr>
                    <th scope="col">Website</th>
                    <th scope="col">Date and time</th>
                    <th scope="col">Provider status</th>
                    <th scope="col">Risk indicator</th>
                    <th scope="col"><span className="sr-only">Details</span></th>
                  </tr>
                </thead>
                <tbody>
                  {records.map((assessment) => (
                    <tr key={assessment.id}>
                      <td className="font-mono">{assessment.target_domain}</td>
                      <td>{formatDate(assessment.created_at)}</td>
                      <td>{assessment.provider_status.replaceAll('_', ' ')}</td>
                      <td><WebsiteRiskBadge level={assessment.risk_level} /></td>
                      <td>
                        <button
                          className="btn btn-secondary user-details-button"
                          type="button"
                          onClick={() => setSelectedAssessment(assessment)}
                          aria-label={`View assessment details for ${assessment.target_domain}`}
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="user-pagination" aria-label="Website history pagination">
              <span>
                Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} of {total}
              </span>
              <div>
                <button
                  className="btn btn-secondary"
                  type="button"
                  onClick={() => setPage((value) => Math.max(1, value - 1))}
                  disabled={page === 1}
                >
                  Previous
                </button>
                <span aria-live="polite">Page {page} of {totalPages}</span>
                <button
                  className="btn btn-secondary"
                  type="button"
                  onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
                  disabled={page === totalPages}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </section>

      {selectedAssessment && (
        <Modal
          isOpen
          onClose={() => setSelectedAssessment(null)}
          title={`Website assessment: ${selectedAssessment.target_domain}`}
          maxWidth="780px"
        >
          <WebsiteAssessmentDetails assessment={selectedAssessment} />
        </Modal>
      )}
    </div>
  );
};

export default WebsiteHistory;
