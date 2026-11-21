export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

export const REFRESH_INTERVAL_MS = 15000; // 15 seconds periodic refresh

export const THREAT_COLORS = {
  NORMAL: '#10b981',      // Emerald
  DOS_DDOS: '#ef4444',    // Red
  PORT_SCAN: '#f59e0b',   // Amber
  BRUTE_FORCE: '#8b5cf6',  // Purple
  WEB_ATTACK: '#ec4899',   // Pink
  BOTNET: '#06b6d4',      // Cyan
  INFILTRATION: '#dc2626'  // Dark Red
};

export const RISK_COLORS = {
  LOW: '#10b981',
  MEDIUM: '#f59e0b',
  HIGH: '#ef4444',
  CRITICAL: '#991b1b',
  INSUFFICIENT_INFORMATION: '#94a3b8',
  ANALYSIS_UNAVAILABLE: '#64748b',
};
