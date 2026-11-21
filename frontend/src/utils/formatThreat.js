import { THREAT_COLORS } from './constants';

export const getThreatColor = (threatType) => {
  if (!threatType) return '#9ca3af';
  return THREAT_COLORS[threatType.toUpperCase()] || '#3b82f6';
};

export const formatThreatLabel = (threatType) => {
  if (!threatType) return 'Unknown';
  return threatType.replace('_', ' ').toUpperCase();
};
