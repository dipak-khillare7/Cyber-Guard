import React, { useState } from 'react';
import DetectionDetailsModal from '../components/detections/DetectionDetailsModal';
import AnalyzeEventFormModal from '../components/detections/AnalyzeEventFormModal';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import EmptyState from '../components/common/EmptyState';
import RiskBadge from '../components/common/RiskBadge';
import Pagination from '../components/common/Pagination';
import { useDetections } from '../hooks/useDetections';
import { formatDate } from '../utils/formatDate';
import { formatThreatLabel } from '../utils/formatThreat';
import { formatConfidence } from '../utils/formatRisk';
import { Activity, Plus, RefreshCw, Eye, Search, Filter } from 'lucide-react';

const Detections = () => {
  const [page, setPage] = useState(1);
  const [limit] = useState(15);
  const [riskFilter, setRiskFilter] = useState('');
  const [threatFilter, setThreatFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const { detections, total, pages, loading, error, refresh } = useDetections({
    page,
    limit,
    risk_level: riskFilter || undefined,
    threat_type: threatFilter || undefined
  });

  const [selectedDetection, setSelectedDetection] = useState(null);
  const [isAnalyzeModalOpen, setIsAnalyzeModalOpen] = useState(false);

  // Client-side quick search filtering on currently loaded page if desired
  const filteredDetections = (detections || []).filter((det) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    const source = (det.source_ip || det.source || '').toLowerCase();
    const threat = (det.predicted_threat || det.threat_type || '').toLowerCase();
    const idStr = String(det.id);
    return source.includes(q) || threat.includes(q) || idStr.includes(q);
  });

  return (
    <div className="detections-page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>AI Threat Detections</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            Machine learning model predictions, confidence metrics, and threat classifications.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-secondary" onClick={refresh} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> {loading ? 'Refreshing...' : 'Refresh'}
          </button>
          <button className="btn btn-primary" onClick={() => setIsAnalyzeModalOpen(true)} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Plus size={16} /> Analyze New Event
          </button>
        </div>
      </div>

      {/* Search & Filter Bar */}
      <div className="table-card" style={{ padding: '1rem 1.25rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: '1 1 250px' }}>
            <Search size={16} color="var(--text-secondary)" />
            <input
              type="text"
              placeholder="Search by ID or Source IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%',
                backgroundColor: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.875rem'
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
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
                <option value="BENIGN">BENIGN / NORMAL</option>
                <option value="DOS">DOS / DDOS</option>
                <option value="BRUTE_FORCE">BRUTE FORCE</option>

                <option value="WEB_ATTACK">WEB ATTACK</option>

              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="table-card">
        {loading && (!detections || detections.length === 0) ? (
          <LoadingState message="Fetching detection history from API..." />
        ) : error ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : filteredDetections.length === 0 ? (
          <EmptyState
            title="No Detections Found"
            message="No threat detections match the selected search query or filters."
            onAction={refresh}
            actionLabel="Reset Filters & Reload"
          />
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-card-header)', textAlign: 'left', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>ID</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Timestamp</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Source IP</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Predicted Threat</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Confidence</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Risk Score</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Risk Level</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Model</th>
                    <th style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDetections.map((det) => (
                    <tr key={det.event_id || det.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>#{det.event_id || det.id}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{formatDate(det.timestamp || det.created_at)}</td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>{det.source_ip || det.source || 'Not reported'}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', fontWeight: 600 }}>{formatThreatLabel(det.detected_threat || det.predicted_threat || det.threat_type)}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', fontFamily: 'monospace' }}>{formatConfidence(det.confidence)}</td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem', fontFamily: 'monospace' }}>{det.risk_score ?? '-'}</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <RiskBadge level={det.risk_level} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {det.model_version || det.model_name || 'Not reported'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <button
                          className="btn btn-secondary"
                          onClick={() => setSelectedDetection(det)}
                          style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                        >
                          <Eye size={14} /> Details
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
              totalItems={total || filteredDetections.length}
              pageSize={limit}
            />
          </>
        )}
      </div>

      {/* Detection Details Modal */}
      {selectedDetection && (
        <DetectionDetailsModal
          isOpen={Boolean(selectedDetection)}
          detection={selectedDetection}
          onClose={() => setSelectedDetection(null)}
        />
      )}

      {/* Analyze Event Form Modal */}
      {isAnalyzeModalOpen && (
        <AnalyzeEventFormModal
          isOpen={isAnalyzeModalOpen}
          onClose={() => setIsAnalyzeModalOpen(false)}
          onSuccess={() => {
            refresh();
          }}
        />
      )}
    </div>
  );
};

export default Detections;
