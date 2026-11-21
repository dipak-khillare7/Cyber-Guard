import api from './api';

export const websiteAssessmentService = {
  create: (url, consentToShare, idempotencyKey) => api.post(
    '/website-analysis/analyze',
    {
      url,
      consent_to_share: consentToShare,
    },
    { headers: { 'Idempotency-Key': idempotencyKey } },
  ),

  getSummary: () => api.get('/website-assessments/summary'),

  getAssessments: (params = {}) => api.get('/website-analysis/history', { params }),

  getAssessment: (assessmentId) => api.get(`/website-analysis/${assessmentId}`),
};
