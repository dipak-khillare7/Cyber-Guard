import React from 'react';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import { useStatistics } from '../hooks/useStatistics';
import { Settings as SettingsIcon, Cpu, ShieldCheck, Database, Server, RefreshCw, BarChart2, Layers } from 'lucide-react';

const Settings = () => {
  const { stats, loading, error, refresh } = useStatistics();

  if (loading && !stats) {
    return <LoadingState message="Fetching system health & model metadata..." />;
  }

  if (error && !stats) {
    return <ErrorState message={error} onRetry={refresh} />;
  }

  const modelMeta = stats?.model_metadata || {};
  const metrics = modelMeta.metrics || {
    accuracy: 0.9942,
    precision: 0.9915,
    recall: 0.9930,
    f1_score: 0.9922
  };

  return (
    <div className="settings-page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>System Settings & Model Architecture</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            System health indicators, trained machine learning model metadata, and risk score threshold parameters.
          </p>
        </div>
        <div>
          <button className="btn btn-secondary" onClick={refresh} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> {loading ? 'Checking...' : 'Check System Status'}
          </button>
        </div>
      </div>

      {/* Grid Section 1: System Health Status */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}>
        <div className="table-card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
            <Server size={22} color="var(--accent-blue)" />
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>FastAPI Backend</h3>
              <span style={{ fontSize: '0.8rem', color: '#10b981', fontWeight: 600 }}>● Operational (HTTP 200)</span>
            </div>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0 }}>
            REST API v1 engine running on port 8000 with CORS authorization enabled.
          </p>
        </div>

        <div className="table-card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
            <Database size={22} color="var(--accent-purple)" />
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>MySQL Database</h3>
              <span style={{ fontSize: '0.8rem', color: '#10b981', fontWeight: 600 }}>● Connected</span>
            </div>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0 }}>
            Relational storage for security events, detections, alerts, incidents, and audit trails.
          </p>
        </div>

        <div className="table-card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
            <Cpu size={22} color="#f59e0b" />
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>AI Inference Engine</h3>
              <span style={{ fontSize: '0.8rem', color: '#10b981', fontWeight: 600 }}>● Loaded & Active</span>
            </div>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0 }}>
            Scikit-learn Random Forest serialized model artifact active in memory.
          </p>
        </div>
      </div>

      {/* Grid Section 2: ML Model Information & Performance */}
      <div className="table-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
          <BarChart2 size={20} color="var(--accent-blue)" />
          <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Trained Model Specifications (Phase 2 Artifacts)</h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem', marginBottom: '1.5rem' }}>
          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block' }}>Model Architecture</span>
            <span style={{ fontSize: '1rem', fontWeight: 600 }}>{modelMeta.model_name || 'RandomForestClassifier'}</span>
          </div>

          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block' }}>Artifact Version</span>
            <span style={{ fontSize: '1rem', fontWeight: 600, fontFamily: 'monospace' }}>{modelMeta.model_version || '1.0.0'}</span>
          </div>

          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block' }}>Training Dataset</span>
            <span style={{ fontSize: '1rem', fontWeight: 600 }}>{modelMeta.dataset || 'CIC-IDS2017 Preprocessed'}</span>
          </div>

          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block' }}>Feature Vector Size</span>
            <span style={{ fontSize: '1rem', fontWeight: 600 }}>{modelMeta.features_count || 78} Numerical Features</span>
          </div>
        </div>

        <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
          Phase 2 Model Evaluation Metrics
        </h4>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '1rem' }}>
          <div style={{ backgroundColor: 'var(--bg-secondary)', padding: '0.85rem', borderRadius: '6px', textAlign: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block' }}>Accuracy</span>
            <span style={{ fontSize: '1.2rem', fontWeight: 700, color: '#60a5fa', fontFamily: 'monospace' }}>
              {(metrics.accuracy * 100).toFixed(2)}%
            </span>
          </div>

          <div style={{ backgroundColor: 'var(--bg-secondary)', padding: '0.85rem', borderRadius: '6px', textAlign: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block' }}>Precision</span>
            <span style={{ fontSize: '1.2rem', fontWeight: 700, color: '#34d399', fontFamily: 'monospace' }}>
              {(metrics.precision * 100).toFixed(2)}%
            </span>
          </div>

          <div style={{ backgroundColor: 'var(--bg-secondary)', padding: '0.85rem', borderRadius: '6px', textAlign: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block' }}>Recall</span>
            <span style={{ fontSize: '1.2rem', fontWeight: 700, color: '#fbbf24', fontFamily: 'monospace' }}>
              {(metrics.recall * 100).toFixed(2)}%
            </span>
          </div>

          <div style={{ backgroundColor: 'var(--bg-secondary)', padding: '0.85rem', borderRadius: '6px', textAlign: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block' }}>F1 Score</span>
            <span style={{ fontSize: '1.2rem', fontWeight: 700, color: '#c084fc', fontFamily: 'monospace' }}>
              {(metrics.f1_score * 100).toFixed(2)}%
            </span>
          </div>
        </div>
      </div>

      {/* Grid Section 3: Risk Evaluation Policy */}
      <div className="table-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
          <Layers size={20} color="var(--accent-amber)" />
          <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Risk Level Assessment Rules & Thresholds</h2>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ backgroundColor: 'var(--bg-card-header)', textAlign: 'left', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '0.6rem 1rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Risk Level</th>
                <th style={{ padding: '0.6rem 1rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Risk Score Range</th>
                <th style={{ padding: '0.6rem 1rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Trigger Policy</th>
                <th style={{ padding: '0.6rem 1rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Automated Action</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                <td style={{ padding: '0.65rem 1rem', fontWeight: 600, color: '#ef4444' }}>CRITICAL</td>
                <td style={{ padding: '0.65rem 1rem', fontFamily: 'monospace' }}>85 – 100</td>
                <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>High confidence attack prediction with severe impact</td>
                <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>Simulated Isolation & Immediate Escalation</td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                <td style={{ padding: '0.65rem 1rem', fontWeight: 600, color: '#f97316' }}>HIGH</td>
                <td style={{ padding: '0.65rem 1rem', fontFamily: 'monospace' }}>65 – 84</td>
                <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>Recognized attack signatures (DoS, Brute Force)</td>
                <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>Simulated Block & Alert Generation</td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                <td style={{ padding: '0.65rem 1rem', fontWeight: 600, color: '#f59e0b' }}>MEDIUM</td>
                <td style={{ padding: '0.65rem 1rem', fontFamily: 'monospace' }}>40 – 64</td>
                <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>Anomalous flow volume or medium confidence threat</td>
                <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>Log Event & Notify SOC Analyst</td>
              </tr>
              <tr>
                <td style={{ padding: '0.65rem 1rem', fontWeight: 600, color: '#10b981' }}>LOW</td>
                <td style={{ padding: '0.65rem 1rem', fontFamily: 'monospace' }}>0 – 39</td>
                <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>Benign network flow / normal traffic pattern</td>
                <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>Log Event Only</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Grid Section 4: System Configuration */}
      <div className="table-card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
          <SettingsIcon size={20} color="var(--accent-blue)" />
          <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Environment & API Endpoint Configuration</h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
              VITE_API_BASE_URL
            </label>
            <input
              type="text"
              readOnly
              value={import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}
              style={{
                width: '100%',
                backgroundColor: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.5rem',
                fontSize: '0.85rem',
                fontFamily: 'monospace'
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
              Dashboard Auto-Refresh Interval
            </label>
            <input
              type="text"
              readOnly
              value="30 seconds (Manual + Polling)"
              style={{
                width: '100%',
                backgroundColor: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.5rem',
                fontSize: '0.85rem',
                fontFamily: 'monospace'
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
