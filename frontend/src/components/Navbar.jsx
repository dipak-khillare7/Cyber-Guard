import React, { useState, useEffect } from 'react';
import { Server, ShieldCheck } from 'lucide-react';
import { healthService } from '../services/api';

const Navbar = () => {
  const [isOnline, setIsOnline] = useState(true);

  useEffect(() => {
    const checkBackend = async () => {
      try {
        await healthService.getHealthStatus();
        setIsOnline(true);
      } catch (err) {
        setIsOnline(false);
      }
    };
    checkBackend();
    const interval = setInterval(checkBackend, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="navbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <ShieldCheck size={20} style={{ color: 'var(--accent-cyan)' }} />
        <span style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
          AI Security Operations Center (Simulation Base)
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
        <div className="navbar-status">
          <span className={`status-dot ${isOnline ? '' : 'status-offline'}`} style={{ backgroundColor: isOnline ? 'var(--accent-emerald)' : 'var(--accent-rose)' }}></span>
          <span>Backend API: {isOnline ? 'ONLINE (v1.0.0)' : 'DISCONNECTED'}</span>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
