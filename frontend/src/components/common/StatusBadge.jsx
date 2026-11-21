import React from 'react';

const StatusBadge = ({ status }) => {
  if (!status) return null;
  const s = status.toUpperCase();
  let badgeClass = 'badge-info';

  if (['RESOLVED', 'CLOSED'].includes(s)) {
    badgeClass = 'badge-low';
  } else if (['NEW', 'OPEN'].includes(s)) {
    badgeClass = 'badge-high';
  } else if (['INVESTIGATING', 'IN_PROGRESS', 'ACKNOWLEDGED'].includes(s)) {
    badgeClass = 'badge-medium';
  } else if (['FALSE_POSITIVE', 'IGNORED'].includes(s)) {
    badgeClass = 'badge-info';
  }

  return <span className={`badge ${badgeClass}`}>{status}</span>;
};

export default StatusBadge;
