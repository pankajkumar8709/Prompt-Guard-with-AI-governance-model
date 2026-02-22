import { api } from './http'
import type {
  AttackTypes,
  ChatRequest,
  ChatResponse,
  SessionTimeline,
  StatsDistribution,
  StatsSnapshot,
  TenantId,
  TimeseriesPoint,
  LiveFeedRow,
  HealthResponse,
  ModelInfoResponse,
} from './types'

export async function getTenants(): Promise<{ tenants: TenantId[] }> {
  const { data } = await api.get('/tenants')
  return data
}

export async function getStats(tenantId?: string): Promise<StatsSnapshot> {
  const url = tenantId && tenantId !== 'all' ? `/tenants/${encodeURIComponent(tenantId)}/stats` : '/stats'
  const { data } = await api.get(url)
  return data
}

export async function getDistribution(tenantId?: string): Promise<StatsDistribution> {
  const { data } = await api.get('/stats/distribution', {
    params: tenantId && tenantId !== 'all' ? { tenant_id: tenantId } : undefined,
  })
  return data
}

export async function getTimeseries(tenantId?: string): Promise<{ points: TimeseriesPoint[] }> {
  const { data } = await api.get('/stats/timeseries', {
    params: tenantId && tenantId !== 'all' ? { tenant_id: tenantId } : undefined,
  })
  return data
}

export async function getAttackTypes(tenantId?: string): Promise<AttackTypes> {
  const { data } = await api.get('/stats/attack-types', {
    params: tenantId && tenantId !== 'all' ? { tenant_id: tenantId } : undefined,
  })
  return data
}

export async function getLiveFeed(tenantId?: string): Promise<{ rows: LiveFeedRow[] }> {
  const { data } = await api.get('/stats/live', {
    params: tenantId && tenantId !== 'all' ? { tenant_id: tenantId } : undefined,
  })
  return data
}

export async function getSessionTimeline(sessionId: string): Promise<SessionTimeline> {
  const { data } = await api.get(`/stats/sessions/${encodeURIComponent(sessionId)}/timeline`)
  return data
}

export async function postChat(message: ChatRequest, tenantId: string): Promise<ChatResponse> {
  const { data } = await api.post('/chat', message, {
    headers: {
      'X-Tenant-ID': tenantId,
    },
  })
  return data
}

export async function getHealth(): Promise<HealthResponse> {
  const { data } = await api.get('/health')
  return data
}

export async function getModelInfo(): Promise<ModelInfoResponse> {
  const { data } = await api.get('/model-info')
  return data
}
