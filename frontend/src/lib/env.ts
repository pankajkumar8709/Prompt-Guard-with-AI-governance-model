export function getApiBaseUrl(): string {
  // Vite exposes env vars on import.meta.env
  const v = (import.meta as any).env?.VITE_API_BASE_URL as string | undefined
  return (v && v.trim()) || 'http://127.0.0.1:8000'
}
