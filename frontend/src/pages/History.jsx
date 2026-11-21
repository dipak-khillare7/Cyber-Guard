import React, { useMemo, useState } from 'react';
import { Database, Eye, Search } from 'lucide-react';
import ErrorState from '../components/common/ErrorState';
import LoadingState from '../components/common/LoadingState';
import Modal from '../components/common/Modal';
import RiskBadge from '../components/common/RiskBadge';
import UserResultDetails from '../components/user/UserResultDetails';
import { useUserActivity } from '../hooks/useUserActivity';
import { formatDate } from '../utils/formatDate';
import { formatThreatLabel } from '../utils/formatThreat';
import { filterAndSortUserHistory, paginateRecords } from '../utils/userPortal';

const PAGE_SIZE = 15;

const History = () => {
  const { activity, loading, error, refresh } = useUserActivity();
  const [search, setSearch] = useState('');
  const [riskLevel, setRiskLevel] = useState('');
  const [threatType, setThreatType] = useState('');
  const [sortOrder, setSortOrder] = useState('newest');
  const [page, setPage] = useState(1);
  const [selectedRecord, setSelectedRecord] = useState(null);

  const allRecords = activity?.events || [];
  const filteredRecords = useMemo(
    () => filterAndSortUserHistory(allRecords, { search, riskLevel, threatType, sortOrder }),
    [allRecords, search, riskLevel, threatType, sortOrder],
  );
  const totalPages = Math.max(1, Math.ceil(filteredRecords.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const visibleRecords = paginateRecords(filteredRecords, currentPage, PAGE_SIZE);
  const threatOptions = [...new Set(allRecords.map(
    (record) => record.alert_id ? record.detected_threat : 'NO_ALERT',
  ))].filter(Boolean).sort();

  const resetPage = (setter) => (event) => {
    setter(event.target.value);
    setPage(1);
  };

  if (loading && !activity) {
    return <LoadingState message="Loading your event history…" />;
  }

  if (error && !activity) {
    return <ErrorState message={error} onRetry={refresh} />;
  }

  return (
    <div className="user-portal-page">
      <header className="user-page-header">
        <div>
          <p className="user-eyebrow">YOUR SUBMISSIONS</p>
          <h1>Security history</h1>
          <p>Search and review events submitted through your account.</p>
        </div>
        <span className="user-history-count">{filteredRecords.length} matching events</span>
      </header>

      {error && (
        <p className="user-inline-error" role="status">
          Could not refresh your history. Showing the last loaded records. {error}
        </p>
      )}

      <section className="user-portal-card user-history-filters" aria-label="Filter event history">
        <div className="user-search-field">
          <Search size={17} aria-hidden="true" />
          <label className="sr-only" htmlFor="history-search">Search your event history</label>
          <input
            id="history-search"
            type="search"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
            placeholder="Search event ID, IP address, protocol, or category"
          />
        </div>
        <div className="user-filter-controls">
          <div className="user-filter-field">
            <label htmlFor="history-risk-filter">Risk</label>
            <select id="history-risk-filter" value={riskLevel} onChange={resetPage(setRiskLevel)}>
              <option value="">All risk levels</option>
              <option value="NO_ALERT">No alert linked</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>
          <div className="user-filter-field">
            <label htmlFor="history-threat-filter">Category</label>
            <select id="history-threat-filter" value={threatType} onChange={resetPage(setThreatType)}>
              <option value="">All categories</option>
              {threatOptions.map((threat) => (
                <option key={threat} value={threat}>
                  {threat === 'NO_ALERT' ? 'No alert linked' : formatThreatLabel(threat)}
                </option>
              ))}
            </select>
          </div>
          <div className="user-filter-field">
            <label htmlFor="history-sort">Date order</label>
            <select id="history-sort" value={sortOrder} onChange={resetPage(setSortOrder)}>
              <option value="newest">Newest first</option>
              <option value="oldest">Oldest first</option>
            </select>
          </div>
        </div>
      </section>

      <section className="user-portal-card user-history-card">
        {visibleRecords.length === 0 ? (
          <div className="user-empty-history">
            <Database size={30} aria-hidden="true" />
            <h2>{allRecords.length ? 'No matching events' : 'No events submitted yet'}</h2>
            <p>{allRecords.length
              ? 'Try another search term or clear one or more filters.'
              : 'Events you submit for analysis will appear here.'}
            </p>
          </div>
        ) : (
          <>
            <div className="user-table-wrap">
              <table className="data-table user-history-table">
                <caption className="sr-only">Your security event history</caption>
                <thead>
                  <tr>
                    <th scope="col">Event</th>
                    <th scope="col">Date and time</th>
                    <th scope="col">Network flow</th>
                    <th scope="col">Threat category</th>
                    <th scope="col">Risk level</th>
                    <th scope="col"><span className="sr-only">Details</span></th>
                  </tr>
                </thead>
                <tbody>
                  {visibleRecords.map((record) => (
                    <tr key={record.event_id}>
                      <td className="font-mono">#{record.event_id}</td>
                      <td>{formatDate(record.timestamp)}</td>
                      <td>
                        <span className="font-mono">{record.source_ip ?? '—'}</span>
                        <span className="user-flow-arrow" aria-hidden="true"> → </span>
                        <span className="font-mono">{record.destination_ip ?? '—'}</span>
                      </td>
                      <td>
                        {record.alert_id
                          ? formatThreatLabel(record.detected_threat)
                          : 'No alert linked'}
                      </td>
                      <td>
                        {record.risk_level
                          ? <RiskBadge level={record.risk_level} />
                          : <span className="user-muted-value">Not retained</span>}
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary user-details-button"
                          type="button"
                          onClick={() => setSelectedRecord(record)}
                          aria-label={`View result details for event ${record.event_id}`}
                        >
                          <Eye size={15} aria-hidden="true" />
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="user-pagination" aria-label="History pagination">
              <span>
                Showing {filteredRecords.length ? (currentPage - 1) * PAGE_SIZE + 1 : 0}
                {'–'}{Math.min(currentPage * PAGE_SIZE, filteredRecords.length)}
                {' '}of {filteredRecords.length}
              </span>
              <div>
                <button
                  className="btn btn-secondary"
                  type="button"
                  onClick={() => setPage((value) => Math.max(1, value - 1))}
                  disabled={currentPage === 1}
                >
                  Previous
                </button>
                <span aria-live="polite">Page {currentPage} of {totalPages}</span>
                <button
                  className="btn btn-secondary"
                  type="button"
                  onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
                  disabled={currentPage === totalPages}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </section>

      {selectedRecord && (
        <Modal
          isOpen
          onClose={() => setSelectedRecord(null)}
          title={`Event #${selectedRecord.event_id} result details`}
          maxWidth="780px"
        >
          <UserResultDetails record={selectedRecord} />
        </Modal>
      )}
    </div>
  );
};

export default History;
