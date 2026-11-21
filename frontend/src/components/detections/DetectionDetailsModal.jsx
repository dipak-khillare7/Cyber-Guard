import React from 'react';
import Modal from '../common/Modal';
import RiskBadge from '../common/RiskBadge';
import { formatDate } from '../../utils/formatDate';
import { formatRiskScore } from '../../utils/formatRisk';
import { Shield, Cpu, Activity, ShieldAlert, PlayCircle } from 'lucide-react';

const DetectionDetailsModal = ({ isOpen = true, onClose, detection }) => {
  if (!detection) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Detection Detail — Event #${detection.event_id}`} maxWidth="750px">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        
        {/* Section 1: Event Information */}
        <div style={{ backgroundColor: 'var(--bg-primary)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: 'var(--accent-blue)', fontWeight: 600 }}>
            <Activity size={18} /> Network Flow Attributes
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.5rem', fontSize: '0.85rem' }}>
            <div><strong>Source IP:</strong> <code className="font-mono">{detection.source_ip || 'N/A'}</code></div>
            <div><strong>Dest IP:</strong> <code className="font-mono">{detection.destination_ip || 'N/A'}</code></div>
            <div><strong>Dest Port:</strong> <code className="font-mono">{detection.destination_port || 'N/A'}</code></div>
            <div><strong>Packets:</strong> <code className="font-mono">{detection.packet_count || 0}</code></div>
            <div><strong>Duration:</strong> <code className="font-mono">{detection.duration ? `${detection.duration} ms` : 'N/A'}</code></div>
            <div><strong>Timestamp:</strong> <code className="font-mono">{formatDate(detection.timestamp)}</code></div>
          </div>
        </div>

        {/* Section 2: AI ML Prediction */}
        <div style={{ backgroundColor: 'var(--bg-primary)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
            <Cpu size={18} /> AI Machine Learning Classification
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.85rem' }}>
            <div>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Predicted Threat Category</p>
              <span className="badge badge-info font-mono" style={{ fontSize: '0.9rem', padding: '0.35rem 0.75rem' }}>
                {detection.detected_threat || detection.prediction?.threat_type}
              </span>
            </div>
            <div>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Model Confidence Estimate</p>
              <span className="font-mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                {detection.confidence ? `${(detection.confidence * 100).toFixed(1)}%` : 'N/A'}
              </span>
            </div>
          </div>

          {/* Probability distribution if available */}
          {detection.prediction?.probabilities && Object.keys(detection.prediction.probabilities).length > 0 && (
            <div style={{ marginTop: '0.85rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-color)' }}>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>Class Probabilities Breakdown:</p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.35rem', fontSize: '0.75rem' }}>
                {Object.entries(detection.prediction.probabilities).map(([cls, prob]) => (
                  <div key={cls} style={{ display: 'flex', justifyContent: 'space-between', backgroundColor: 'var(--bg-secondary)', padding: '0.25rem 0.5rem', borderRadius: '4px' }}>
                    <span>{cls}</span>
                    <span className="font-mono">{(prob * 100).toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Section 3: Risk Assessment Engine */}
        <div style={{ backgroundColor: 'var(--bg-primary)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: 'var(--accent-amber)', fontWeight: 600 }}>
            <ShieldAlert size={18} /> Risk Engine Assessment
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
            <RiskBadge level={detection.risk_level || detection.risk?.level} />
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Risk Score: <strong className="font-mono">{formatRiskScore(detection.risk?.score || 0)}</strong>
            </span>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', backgroundColor: 'var(--bg-secondary)', padding: '0.65rem', borderRadius: '6px' }}>
            {detection.message || detection.risk?.reason || 'No elevated risk factors.'}
          </p>
        </div>

        {/* Section 4: Simulated Response Policy */}
        <div style={{ backgroundColor: 'var(--bg-primary)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--accent-emerald)', fontWeight: 600 }}>
            <PlayCircle size={18} /> Response Action Policy
          </div>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            <div>Action: <strong>{detection.response?.action_type || 'LOG'}</strong> (Status: <span className="font-mono">{detection.response?.action_status || 'SIMULATED'}</span>)</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', marginTop: '0.35rem' }}>
              ℹ️ Simulation Mode: Safe non-destructive audit log. No real firewall or network interface modified.
            </div>
          </div>
        </div>

      </div>
    </Modal>
  );
};

export default DetectionDetailsModal;
