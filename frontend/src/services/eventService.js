import api from './api';

export const eventService = {
  getEvents: (params = {}) => api.get('/events', { params }),
};
