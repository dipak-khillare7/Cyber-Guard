import { formatDate } from './formatDate';

export { formatDate };

export const formatConfidence = (confidence) => {
  if (confidence === undefined || confidence === null) return 'N/A';
  return `${(confidence * 100).toFixed(1)}%`;
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
