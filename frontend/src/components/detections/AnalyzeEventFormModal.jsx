import React, { useState } from 'react';
import Modal from '../common/Modal';
import { detectionService } from '../../services/detectionService';
import { Play, Shield, RefreshCw, AlertCircle, CheckCircle } from 'lucide-react';

const AnalyzeEventFormModal = ({ isOpen = true, onClose, onSuccess }) => {
  const [formData, setFormData] = useState({
    source_ip: '192.168.1.150',
    destination_ip: '10.0.0.1',
    source_port: 54321,
    destination_port: 80,
    protocol: 'TCP',
    duration: 150000,
    packet_count: 500,
    byte_count: 250000,
    syn_flag_count: 1,
    ack_flag_count: 1
  });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (loading) return;
    setLoading(true);
    setErrorMsg(null);
    setResult(null);
    try {
      const res = await detectionService.analyzeEvent(formData);
      const data = res.data?.data || res.data;
      setResult(data);
      if (typeof onSuccess === 'function') {
        try {
          onSuccess(data);
        } catch (refreshErr) {
          console.warn('Optional dashboard refresh callback warning:', refreshErr);
        }
      }
    } catch (err) {
      const detail = err.response?.data?.detail?.message || err.response?.data?.detail || err.message || 'AI Detection Service Error';
      setErrorMsg(typeof detail === 'object' ? JSON.stringify(detail) : String(detail));
    } finally {
      setLoading(false);
    }
  };

  const applyPreset = (presetType) => {
    setResult(null);
    setErrorMsg(null);
    if (presetType === 'NORMAL') {
      setFormData({
        source_ip: '192.168.1.100',
        destination_ip: '10.0.0.1',
        source_port: 52140,
        destination_port: 80,
        protocol: 'TCP',
        duration: 50000.0,
        packet_count: 15,
        byte_count: 15000,
        syn_flag_count: 0,
        ack_flag_count: 1
      });
    } else if (presetType === 'DOS') {
      setFormData({
        source_ip: '45.33.32.156',
        destination_ip: '10.0.0.1',
        source_port: 48922,
        destination_port: 80,
        protocol: 'TCP',
        duration: 250000.0,
        packet_count: 1000,
        byte_count: 500000,
        syn_flag_count: 1,
        ack_flag_count: 1
      });
    } else if (presetType === 'BOTNET') {
      setFormData({
        source_ip: '172.16.0.55',
        destination_ip: '10.0.0.1',
        source_port: 33412,
        destination_port: 22,
        protocol: 'TCP',
        duration: 850000.0,
        packet_count: 3500,
        byte_count: 1800000,
        syn_flag_count: 1,
        ack_flag_count: 0
      });
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Analyze Security Event (AI Inference Engine)" maxWidth="650px">
      {/* Preset Quick Loader Buttons */}
      <div style={{ marginBottom: '1.25rem', backgroundColor: 'var(--bg-secondary)', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.5rem', fontWeight: 600 }}>
          Quick Load Sample Simulation Payloads:
        </span>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => applyPreset('NORMAL')}
            style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem' }}
          >
            Normal Traffic Flow
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => applyPreset('DOS')}
            style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', color: '#ef4444' }}
          >
            DoS / DDoS Attack
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => applyPreset('BOTNET')}
            style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', color: '#a855f7' }}
          >
            Botnet Activity
          </button>
        </div>
      </div>

      {errorMsg && (
        <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.4)', color: '#fca5a5', padding: '0.75rem 1rem', borderRadius: '6px', marginBottom: '1rem', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertCircle size={16} />
          <div>{errorMsg}</div>
        </div>
      )}

      {result && (
        <div style={{ backgroundColor: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.4)', color: '#6ee7b7', padding: '0.85rem 1rem', borderRadius: '6px', marginBottom: '1rem', fontSize: '0.85rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, marginBottom: '0.35rem' }}>
            <CheckCircle size={18} /> Analysis Complete — Event #{result.event_id} Logged
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.5rem', marginTop: '0.5rem', fontFamily: 'monospace', fontSize: '0.8rem' }}>
            <div><strong>Threat:</strong> {result.prediction?.threat_type || 'NORMAL'}</div>
            <div><strong>Confidence:</strong> {((result.prediction?.confidence || 0) * 100).toFixed(1)}%</div>
            <div><strong>Risk Score:</strong> {result.risk?.score ?? result.risk_score ?? '-'}</div>
            <div><strong>Risk Level:</strong> {result.risk?.level ?? result.risk_level ?? 'Not reported'}</div>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem', marginBottom: '1.25rem', fontSize: '0.85rem' }}>
          <div>
            <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Source IP</label>
            <input
              type="text"
              required
              value={formData.source_ip}
              onChange={(e) => setFormData({ ...formData, source_ip: e.target.value })}
              style={{ width: '100%', padding: '0.45rem 0.6rem', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)', border: '1px solid var(--border-color)', borderRadius: '6px' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Destination IP</label>
            <input
              type="text"
              required
              value={formData.destination_ip}
              onChange={(e) => setFormData({ ...formData, destination_ip: e.target.value })}
              style={{ width: '100%', padding: '0.45rem 0.6rem', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)', border: '1px solid var(--border-color)', borderRadius: '6px' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Source Port</label>
            <input
              type="number"
              min="0"
              max="65535"
              value={formData.source_port}
              onChange={(e) => setFormData({ ...formData, source_port: parseInt(e.target.value) || 0 })}
              style={{ width: '100%', padding: '0.45rem 0.6rem', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)', border: '1px solid var(--border-color)', borderRadius: '6px' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Destination Port</label>
            <input
              type="number"
              min="0"
              max="65535"
              value={formData.destination_port}
              onChange={(e) => setFormData({ ...formData, destination_port: parseInt(e.target.value) || 80 })}
              style={{ width: '100%', padding: '0.45rem 0.6rem', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)', border: '1px solid var(--border-color)', borderRadius: '6px' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Flow Duration (ms)</label>
            <input
              type="number"
              min="0"
              step="any"
              value={formData.duration}
              onChange={(e) => setFormData({ ...formData, duration: parseFloat(e.target.value) || 0 })}
              style={{ width: '100%', padding: '0.45rem 0.6rem', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)', border: '1px solid var(--border-color)', borderRadius: '6px' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Packet Count</label>
            <input
              type="number"
              min="1"
              value={formData.packet_count}
              onChange={(e) => setFormData({ ...formData, packet_count: parseInt(e.target.value) || 1 })}
              style={{ width: '100%', padding: '0.45rem 0.6rem', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)', border: '1px solid var(--border-color)', borderRadius: '6px' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Byte Count</label>
            <input
              type="number"
              min="0"
              value={formData.byte_count}
              onChange={(e) => setFormData({ ...formData, byte_count: parseInt(e.target.value) || 0 })}
              style={{ width: '100%', padding: '0.45rem 0.6rem', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)', border: '1px solid var(--border-color)', borderRadius: '6px' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Protocol</label>
            <select
              value={formData.protocol}
              onChange={(e) => setFormData({ ...formData, protocol: e.target.value })}
              style={{ width: '100%', padding: '0.45rem 0.6rem', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)', border: '1px solid var(--border-color)', borderRadius: '6px' }}
            >
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>
        </div>

        <div className="modal-footer" style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {result ? 'Close' : 'Cancel'}
          </button>
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? <RefreshCw className="animate-spin" size={14} /> : <Play size={14} />}
            {loading ? 'Analyzing Event...' : 'Run AI Detection'}
          </button>
        </div>
      </form>
    </Modal>
  );
};

export default AnalyzeEventFormModal;
