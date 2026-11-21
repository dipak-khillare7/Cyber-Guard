import api from './api';

export const incidentService = {
  getIncidents: (params) => api.get('/incidents', { params }),
  getIncidentById: (id) => api.get(`/incidents/${id}`),
  updateIncidentStatus: (id, updateData) => api.patch(`/incidents/${id}`, updateData),
  triggerResponseAction: (id, actionData) => api.post(`/incidents/${id}/response`, actionData),
};
