import React from 'react';
import Modal from '../common/Modal';
import { formatDate } from '../../utils/formatDate';
import { PlayCircle, ShieldCheck } from 'lucide-react';

const ResponseDetailsModal = ({ isOpen = true, onClose, response, actionObj }) => {
  const targetAction = response || actionObj;
  if (!targetAction) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Simulated Response Detail — Action #${targetAction.id}`} maxWidth="600px">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.9rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <PlayCircle size={20} style={{ color: 'var(--accent-emerald)' }} />
            <span style={{ fontWeight: 600, fontSize: '1.05rem' }}>{targetAction.action_type}</span>
          </div>
          <span className="badge badge-low">{targetAction.action_status}</span>
        </div>

        <div style={{ backgroundColor: 'var(--bg-primary)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.85rem' }}>
            <div><strong>Incident Ref:</strong> <span className="font-mono">#{targetAction.incident_id}</span></div>
            <div><strong>Alert Ref:</strong> <span className="font-mono">{targetAction.alert_id ? `#${targetAction.alert_id}` : 'N/A'}</span></div>
            <div><strong>Event Ref:</strong> <span className="font-mono">{targetAction.event_id ? `#${targetAction.event_id}` : 'N/A'}</span></div>
            <div><strong>Threat Type:</strong> <span className="font-mono">{targetAction.threat_type || 'N/A'}</span></div>
            <div><strong>Severity:</strong> <span className="font-mono">{targetAction.severity || 'N/A'}</span></div>
            <div><strong>Executed At:</strong> <span className="font-mono">{formatDate(targetAction.executed_at)}</span></div>
          </div>
        </div>

        <div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 500 }}>Action Execution Log</p>
          <div style={{ backgroundColor: 'var(--bg-primary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
            {targetAction.description}
          </div>
        </div>

        <div style={{ backgroundColor: 'rgba(6, 182, 212, 0.1)', border: '1px solid rgba(6, 182, 212, 0.3)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
          <ShieldCheck size={16} style={{ display: 'inline', marginRight: '0.35rem' }} />
          <strong>Safe Academic Simulation:</strong> This mitigation policy was recorded strictly in Simulation Mode. No real network connections, host interfaces, or system accounts were altered.
        </div>
      </div>
    </Modal>
  );
};

export default ResponseDetailsModal;
