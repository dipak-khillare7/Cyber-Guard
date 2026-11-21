import React, { useState } from 'react';
import Modal from '../common/Modal';
import RiskBadge from '../common/RiskBadge';
import StatusBadge from '../common/StatusBadge';
import { formatDate } from '../../utils/formatDate';
import { alertService } from '../../services/alertService';
import { AlertTriangle, CheckCircle } from 'lucide-react';

const AlertDetailsModal = ({ isOpen = true, onClose, alert: alertProp, alertObj, onStatusUpdated }) => {
  const [updating, setUpdating] = useState(false);
  const targetAlert = alertProp || alertObj;

  if (!targetAlert) return null;

  const handleStatusChange = async (newStatus) => {
    setUpdating(true);
    try {
      await alertService.updateAlertStatus(targetAlert.id, newStatus);
      if (onStatusUpdated) onStatusUpdated();
      onClose();
    } catch (err) {
      window.alert('Failed to update alert status: ' + (err.response?.data?.error?.message || err.message));
    } finally {
      setUpdating(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Alert Detail — #${targetAlert.id}`} maxWidth="600px">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.9rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={20} style={{ color: 'var(--accent-amber)' }} />
            <span style={{ fontWeight: 600, fontSize: '1.05rem' }}>{targetAlert.threat_type}</span>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <RiskBadge level={targetAlert.risk_level} />
            <StatusBadge status={targetAlert.status} />
          </div>
        </div>

        <div style={{ backgroundColor: 'var(--bg-primary)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.85rem' }}>
            <div><strong>Detection Confidence:</strong> <span className="font-mono">{targetAlert.confidence ? `${(targetAlert.confidence * 100).toFixed(1)}%` : 'N/A'}</span></div>
            <div><strong>Created:</strong> <span className="font-mono">{formatDate(targetAlert.created_at)}</span></div>
            <div><strong>Related Event ID:</strong> <span className="font-mono">#{targetAlert.event_id || 'N/A'}</span></div>
          </div>
        </div>

        <div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 500 }}>Alert Notification Message</p>
          <div style={{ backgroundColor: 'var(--bg-primary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
            {targetAlert.message}
          </div>
        </div>

        {/* Update Status Controls */}
        <div style={{ marginTop: '0.5rem', paddingTop: '0.85rem', borderTop: '1px solid var(--border-color)' }}>
          <p style={{ fontSize: '0.85rem', fontWeight: 500, marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>Update Alert Lifecycle Status:</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {['ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((st) => (
              <button
                key={st}
                disabled={updating || targetAlert.status === st}
                className={`btn ${targetAlert.status === st ? 'btn-primary' : 'btn-secondary'}`}
                style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem' }}
                onClick={() => handleStatusChange(st)}
              >
                <CheckCircle size={12} /> {st}
              </button>
            ))}
          </div>
        </div>
      </div>
    </Modal>
  );
};

export default AlertDetailsModal;
