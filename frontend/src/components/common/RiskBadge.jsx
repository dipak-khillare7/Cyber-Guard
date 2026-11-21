import React from 'react';
import { getRiskBadgeClass } from '../../utils/formatRisk';

const RiskBadge = ({ level }) => {
  if (!level) return null;
  const badgeClass = getRiskBadgeClass(level);
  return <span className={`badge ${badgeClass}`}>{level}</span>;
};

export default RiskBadge;
