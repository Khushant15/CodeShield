/**
 * services/api.js
 * Axios API client with detailed error surfacing.
 */
import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || '';

const client = axios.create({
  baseURL: BASE_URL,
  timeout: 90_000, // 90s — AI can be slow
  headers: { 'Content-Type': 'application/json' },
});

// Attach optional API key
client.interceptors.request.use((cfg) => {
  const key = import.meta.env.VITE_API_KEY;
  if (key) cfg.headers['x-api-key'] = key;
  return cfg;
});

// Normalize errors for display
client.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.code === 'ECONNABORTED') {
      throw new Error('Request timed out — the server may be overloaded. Try again.');
    }
    if (!err.response) {
      throw new Error('Cannot reach the server. Make sure the backend is running on port 4000.');
    }

    const data = err.response.data;
    const msg  =
      data?.error ||
      (Array.isArray(data?.details) ? data.details.join(', ') : null) ||
      `Server error ${err.response.status}`;

    throw new Error(msg);
  }
);

/**
 * Analyze code for security vulnerabilities.
 * @param {{ code: string, language: string }} payload
 */
export async function analyzeCode(payload) {
  const { data } = await client.post('/analyze', payload);
  return data;
}

export async function checkHealth() {
  const { data } = await client.get('/health');
  return data;
}

export async function testAI() {
  const { data } = await client.get('/health/ai');
  return data;
}
