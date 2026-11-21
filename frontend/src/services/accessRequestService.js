import api from './api';

export const accessRequestService = {
  getMyAnalystRequest: () => api.get('/access-requests/analyst/me'),
  requestAnalystAccess: () => api.post('/access-requests/analyst'),
  listPendingAnalystRequests: (params = {}) => api.get('/access-requests/analyst', { params }),
  decideAnalystRequest: (requestId, decision) => api.post(
    `/access-requests/analyst/${requestId}/decision`,
    { decision },
  ),
};
