import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000,
});

// Request Interceptor: Attach Authorization Bearer token if present
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('soc_token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response Interceptor: Uniform error handling & 401 session expiration
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      // Unauthenticated / expired session handling
      if (error.response.status === 401) {
        localStorage.removeItem('soc_token');
        localStorage.removeItem('soc_user');
        // Do not force reload if already on login page
        if (!window.location.pathname.includes('/login')) {
          window.location.href = '/login?expired=true';
        }
      }
      
      const detail = error.response.data?.detail || error.response.data?.message;
      const validationErrors = error.response.data?.errors;
      const validationMessage = Array.isArray(validationErrors)
        ? validationErrors.map((item) => {
          const field = Array.isArray(item.loc) ? item.loc[item.loc.length - 1] : 'Request';
          return `${field}: ${item.msg}`;
        }).join(' ')
        : '';
      const errorMsg = validationMessage || (
        typeof detail === 'string'
          ? detail
          : typeof detail?.message === 'string'
            ? detail.message
            : JSON.stringify(detail)
      );
      return Promise.reject(new Error(errorMsg || `API Error ${error.response.status}`));
    } else if (error.request) {
      return Promise.reject(new Error('Backend service is unreachable. Please verify server status.'));
    }
    return Promise.reject(error);
  }
);

export default api;
