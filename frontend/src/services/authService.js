import api from './api';

export const authService = {
  register: async (registrationData) => {
    const response = await api.post('/auth/register', registrationData);
    return response.data;
  },

  verifyEmail: async (email, otp) => {
    const response = await api.post('/auth/verify-email', { email, otp });
    return response.data;
  },

  resendVerification: async (email) => {
    const response = await api.post('/auth/resend-verification', { email });
    return response.data;
  },

  login: async (username, password) => {
    const response = await api.post('/auth/login', { username, password });
    if (response.data?.access_token) {
      localStorage.setItem('soc_token', response.data.access_token);
      localStorage.setItem('soc_user', JSON.stringify(response.data.user));
    }
    return response.data;
  },

  getCurrentUser: async () => {
    const response = await api.get('/auth/me');
    return response.data;
  },

  logout: async () => {
    try {
      await api.post('/auth/logout');
    } catch (e) {
      // Ignore network failure on logout
    } finally {
      localStorage.removeItem('soc_token');
      localStorage.removeItem('soc_user');
    }
  },

  getUsers: async (params = {}) => {
    const response = await api.get('/auth/users', { params });
    return response.data;
  },

  createUser: async (userData) => {
    const response = await api.post('/auth/users', userData);
    return response.data;
  },

  getAuditLogs: async (params = {}) => {
    const response = await api.get('/audit-logs', { params });
    return response.data;
  }
};
