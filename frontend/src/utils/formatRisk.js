import { RISK_COLORS } from './constants';

export const getRiskColor = (riskLevel) => {
  if (!riskLevel) return '#9ca3af';
  return RISK_COLORS[riskLevel.toUpperCase()] || '#9ca3af';
};

export const getRiskBadgeClass = (riskLevel) => {
  switch (riskLevel?.toUpperCase()) {
    case 'CRITICAL':
      return 'badge-critical';
    case 'HIGH':
      return 'badge-high';
    case 'MEDIUM':
      return 'badge-medium';
    case 'LOW':
      return 'badge-low';
    default:
      return 'badge-info';
  }
};

export const formatRiskScore = (score) => {
  if (score === undefined || score === null) return 'Not reported';
  const numScore = typeof score === 'number' ? score : parseFloat(score);
  return `${numScore.toFixed(2)}/1.00`;
};

export const formatConfidence = (confidence) => {
  if (confidence === undefined || confidence === null) return 'Not reported';
  const val = typeof confidence === 'number' ? confidence : parseFloat(confidence);
  if (isNaN(val)) return '0.0%';
  if (val <= 1.0) {
    return `${(val * 100).toFixed(1)}%`;
  }
  return `${val.toFixed(1)}%`;
};
