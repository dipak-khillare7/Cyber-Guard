import React from 'react';

const StatCard = ({ title, value, icon: Icon, color = 'var(--accent-blue)', note }) => {
  return (
    <div className="stat-card">
      <div>
        <div className="stat-title">{title}</div>
        <div className="stat-value">{value !== undefined && value !== null ? value : '—'}</div>
        {note && <div className="stat-note">{note}</div>}
      </div>
      {Icon && (
        <div className="stat-icon-wrapper" style={{ color: color, backgroundColor: `${color}15` }}>
          <Icon size={24} />
        </div>
      )}
    </div>
  );
};

export default StatCard;
