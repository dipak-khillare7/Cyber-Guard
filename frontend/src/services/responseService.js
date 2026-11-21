import api from './api';

export const responseService = {
  getResponseActions: (params) => api.get('/response-actions', { params }),
  getResponses: (params) => api.get('/response-actions', { params }),
};

