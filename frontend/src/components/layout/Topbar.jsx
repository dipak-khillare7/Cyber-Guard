import React, { useState, useEffect, useCallback } from 'react';
import { ShieldCheck, RefreshCw, Cpu, Database, User, LogOut } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import api from '../../services/api';
import PortalSwitcher from './PortalSwitcher';

const Topbar = ({ onRefresh }) => {
  const { user, isAuthenticated, logout } = useAuth();
  const [backendStatus, setBackendStatus] = useState('CHECKING');
  const [dbStatus, setDbStatus] = useState('CHECKING');

  const checkHealth = useCallback(async () => {
    setBackendStatus('CHECKING');
    try {
      const res = await api.get('/health');
      setBackendStatus(res.data?.status === 'healthy' ? 'HEALTHY' : 'DEGRADED');
      setDbStatus(res.data?.database === 'healthy' ? 'CONNECTED' : 'DEGRADED');
    } catch {
      setBackendStatus('OFFLINE');
      setDbStatus('DISCONNECTED');
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 20000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  const getRoleBadgeStyle = (role) => {
    switch (role) {
      case 'ADMIN':
        return { backgroundColor: 'rgba(239, 68, 68, 0.2)', color: '#fca5a5', border: '1px solid rgba(239, 68, 68, 0.4)' };
      case 'ANALYST':
        return { backgroundColor: 'rgba(245, 158, 11, 0.2)', color: '#fcd34d', border: '1px solid rgba(245, 158, 11, 0.4)' };
      default:
        return { backgroundColor: 'rgba(59, 130, 246, 0.2)', color: '#93c5fd', border: '1px solid rgba(59, 130, 246, 0.4)' };
    }
  };

  return (
    <header className="navbar soc-topbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <ShieldCheck size={22} style={{ color: 'var(--accent-cyan)' }} />
        <div>
          <span style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            SOC Monitoring Console
          </span>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block' }}>
            Academic Research Prototype (Safe Simulation Mode)
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
        {/* System Health Component Statuses */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <span className="status-dot" style={{ backgroundColor: backendStatus === 'HEALTHY' ? 'var(--accent-emerald)' : 'var(--accent-rose)' }}></span>
            <span>API: {backendStatus}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Database size={14} style={{ color: dbStatus === 'CONNECTED' ? 'var(--accent-emerald)' : 'var(--accent-rose)' }} />
            <span>DB: {dbStatus}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Cpu size={14} style={{ color: 'var(--accent-cyan)' }} />
            <span title="Model health is not exposed by the current health API">ML Model: Not reported</span>
          </div>
          <button
            onClick={async () => {
              await checkHealth();
              if (typeof onRefresh === 'function') onRefresh();
            }}
            title="Refresh System Health Status"
            aria-label="Refresh System Health Status"
            style={{
              backgroundColor: 'transparent',
              border: 'none',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              padding: '0.2rem',
              borderRadius: '4px'
            }}
          >
            <RefreshCw size={14} className={backendStatus === 'CHECKING' ? 'animate-spin' : ''} />
          </button>
        </div>

        <PortalSwitcher />

        {/* User Account & Logout Control */}
        {isAuthenticated && user && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', borderLeft: '1px solid var(--border-color)', paddingLeft: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div
                style={{
                  width: '28px',
                  height: '28px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--bg-secondary)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--text-primary)'
                }}
              >
                <User size={14} />
              </div>
              <div>
                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', lineHeight: 1.1 }}>
                  {user.username}
                </span>
                <span
                  style={{
                    fontSize: '0.65rem',
                    padding: '0.05rem 0.35rem',
                    borderRadius: '3px',
                    fontFamily: 'monospace',
                    fontWeight: 600,
                    display: 'inline-block',
                    ...getRoleBadgeStyle(user.role)
                  }}
                >
                  {user.role}
                </span>
              </div>
            </div>

            <button
              onClick={logout}
              title="Sign Out"
              style={{
                backgroundColor: 'transparent',
                border: '1px solid var(--border-color)',
                color: 'var(--text-secondary)',
                borderRadius: '6px',
                padding: '0.35rem 0.5rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.3rem',
                fontSize: '0.75rem'
              }}
            >
              <LogOut size={14} /> Logout
            </button>
          </div>
        )}
      </div>
    </header>
  );
};

export default Topbar;
