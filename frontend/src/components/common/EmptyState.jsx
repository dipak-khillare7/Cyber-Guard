import React from 'react';
import { Database } from 'lucide-react';

const EmptyState = ({ message = 'No data records found in database.' }) => {
  return (
    <div className="empty-state">
      <Database size={32} style={{ color: 'var(--text-muted)', margin: '0 auto 0.75rem' }} />
      <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>{message}</p>
    </div>
  );
};

export default EmptyState;
