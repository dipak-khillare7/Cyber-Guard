import React, { useState } from 'react';
import Modal from '../common/Modal';
import RiskBadge from '../common/RiskBadge';
import StatusBadge from '../common/StatusBadge';
import { formatDate } from '../../utils/formatDate';
import { incidentService } from '../../services/incidentService';
import { ShieldAlert, GitCommit, CheckCircle, Play } from 'lucide-react';

const IncidentDetailsModal = ({ isOpen = true, onClose, incident, onStatusUpdated }) => {
  const [updating, setUpdating] = useState(false);

  if (!incident) return null;

  const handleStatusChange = async (newStatus) => {
    setUpdating(true);
    try {
      await incidentService.updateIncidentStatus(incident.id, { status: newStatus });
      if (onStatusUpdated) onStatusUpdated();
      onClose();
    } catch (err) {
      alert('Failed to update incident status: ' + (err.response?.data?.error?.message || err.message));
    } finally {
      setUpdating(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Incident Detail — Case #${incident.id}`} maxWidth="700px">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', fontSize: '0.9rem' }}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: 'var(--bg-primary)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldAlert size={20} style={{ color: 'var(--accent-purple)' }} />
            <div>
              <span style={{ fontWeight: 600 }}>{incident.threat_type}</span>
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)' }} className="font-mono">Created: {formatDate(incident.created_at)}</span>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <RiskBadge level={incident.severity} />
            <StatusBadge status={incident.status} />
          </div>
        </div>

        {/* Description */}
        <div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 500 }}>Case Description</p>
          <div style={{ backgroundColor: 'var(--bg-primary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
            {incident.description}
          </div>
        </div>

        {/* Chronological Lifecycle Timeline */}
        <div style={{ backgroundColor: 'var(--bg-primary)', padding: '1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
          <p style={{ color: 'var(--accent-cyan)', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <GitCommit size={16} /> Chronological Incident Lifecycle Timeline
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', borderLeft: '2px solid var(--accent-blue)', paddingLeft: '1rem', marginLeft: '0.5rem', fontSize: '0.8rem' }}>
            <div>
              <strong style={{ color: 'var(--accent-blue)' }}>1. Security Event Ingested</strong>
              <span style={{ display: 'block', color: 'var(--text-muted)' }} className="font-mono">{formatDate(incident.created_at)}</span>
            </div>
            <div>
              <strong style={{ color: 'var(--accent-cyan)' }}>2. AI Detection & Risk Evaluation</strong>
              <span style={{ display: 'block', color: 'var(--text-muted)' }}>Classified as {incident.threat_type} ({incident.severity} Risk)</span>
            </div>
            <div>
              <strong style={{ color: 'var(--accent-amber)' }}>3. Alert & Incident Escalation</strong>
              <span style={{ display: 'block', color: 'var(--text-muted)' }}>Triggered Alert #{incident.alert_id || 'Auto'} → Incident #{incident.id}</span>
            </div>
            {incident.response_actions && incident.response_actions.length > 0 && (
              <div>
                <strong style={{ color: 'var(--accent-emerald)' }}>4. Safe Simulation Response Executed</strong>
                {incident.response_actions.map((act) => (
                  <span key={act.id} style={{ display: 'block', color: 'var(--text-secondary)' }}>
                    • {act.action_type}: {act.description} (<span className="font-mono">{act.action_status}</span>)
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Status update controls */}
        <div style={{ paddingTop: '0.85rem', borderTop: '1px solid var(--border-color)' }}>
          <p style={{ fontSize: '0.85rem', fontWeight: 500, marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>Incident Resolution Control:</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', 'CLOSED'].map((st) => (
              <button
                key={st}
                disabled={updating || incident.status === st}
                className={`btn ${incident.status === st ? 'btn-primary' : 'btn-secondary'}`}
                style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem' }}
                onClick={() => handleStatusChange(st)}
              >
                <CheckCircle size={12} /> Mark as {st}
              </button>
            ))}
          </div>
        </div>

      </div>
    </Modal>
  );
};

export default IncidentDetailsModal;
