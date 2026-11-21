import React from 'react';
import { getRiskBadgeClass } from '../utils/formatters';

const StatusBadge = ({ level }) => {
  if (!level) return null;
  const badgeClass = getRiskBadgeClass(level);
  return <span className={`badge ${badgeClass}`}>{level}</span>;
};

export default StatusBadge;
