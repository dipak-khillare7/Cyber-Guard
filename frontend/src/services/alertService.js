import api from './api';

export const alertService = {
  getAlerts: (params) => api.get('/alerts', { params }),
  getAlertById: (id) => api.get(`/alerts/${id}`),
  updateAlertStatus: (id, status) => api.patch(`/alerts/${id}`, { status }),
};
