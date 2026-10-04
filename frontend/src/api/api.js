/**
 * PhishGuard AI – API Client
 * Single source of truth for all backend communication.
 * All backend URLs are defined here.
 */

import axios from 'axios';

// ── Backend base URL ────────────────────────────────────────
const BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  },
});

// ── Response interceptor for clean error messages ───────────
api.interceptors.response.use(
  (response) => response.data,
  (error) => {
    if (error.code === 'ERR_NETWORK' || error.code === 'ECONNREFUSED') {
      return Promise.reject({
        message: 'Cannot connect to the backend server. Please ensure the FastAPI server is running on port 8000.',
        code: 'BACKEND_UNAVAILABLE',
      });
    }

    const detail = error.response?.data?.detail || error.response?.data?.error;
    const status = error.response?.status;

    if (status === 422) {
      return Promise.reject({ message: detail || 'Invalid input provided.', code: 'VALIDATION_ERROR' });
    }
    if (status === 503) {
      return Promise.reject({ message: detail || 'ML model not available. Please train the model first.', code: 'MODEL_UNAVAILABLE' });
    }
    if (status === 404) {
      return Promise.reject({ message: detail || 'Resource not found.', code: 'NOT_FOUND' });
    }

    return Promise.reject({
      message: detail || 'An unexpected error occurred. Please try again.',
      code: 'UNKNOWN_ERROR',
    });
  }
);

// ── API functions ───────────────────────────────────────────

/** Health check */
export const checkHealth = () => api.get('/api/health');

/**
 * Predict whether a URL is phishing or legitimate.
 * @param {string} url - The URL to analyze
 */
export const predictUrl = (url) =>
  api.post('/api/predict', { url });

/** Get dashboard statistics */
export const getDashboard = () => api.get('/api/dashboard');

/** Get scan history */
export const getHistory = () => api.get('/api/history');

/** Clear all scan history */
export const clearHistory = () => api.delete('/api/history');

/** Get model performance metrics */
export const getModelMetrics = () => api.get('/api/model/metrics');

/** Get feature list */
export const getModelFeatures = () => api.get('/api/model/features');

export default api;
