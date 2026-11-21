import api from './api';

export const detectionService = {
  analyzeEvent: (eventData) => api.post('/detection/analyze', eventData),
  getDetectionHistory: (params) => api.get('/detection/history', { params }),
  getDetectionTrend: (hours = 24) => api.get('/detection/trend', { params: { hours } }),
};
