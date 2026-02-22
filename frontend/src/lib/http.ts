import axios from 'axios'
import { getApiBaseUrl } from './env'

export const api = axios.create({
  baseURL: getApiBaseUrl(),
  timeout: 60_000,
})

// Helpful in development when backend is down
api.interceptors.response.use(
  (r) => r,
  (err) => {
    // Keep original error but normalize message
    const msg = err?.message || 'Network error'
    err.message = msg
    return Promise.reject(err)
  },
)
