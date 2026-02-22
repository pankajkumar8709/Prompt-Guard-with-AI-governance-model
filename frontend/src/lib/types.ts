export type TenantId = string

export type StatsSnapshot = {
  total_requests: number
  blocked: number
  warned: number
  whitelist_hits: number
  hard_block_hits: number
  model_classified?: number
}

export type StatsDistribution = Record<string, number>

export type TimeseriesPoint = { hour: string; count: number }

export type AttackTypes = Record<string, number>

export type LiveFeedRow = {
  ts: string
  tenant_id: string
  label: string
  confidence: number
  filter_stage: string
  is_safe: boolean
  text_length: number

  risk_level?: string | null
  attack_types?: string | null
  enforcement_action?: string | null
  session_id?: string | null
  cumulative_risk_score?: number | null
  inference_ms?: number | null
}

export type HealthResponse = {
  status: string
  architecture?: string
  security_backend?: 'self_governance' | 'legacy'
  layers?: string[]
  db_connected?: boolean
  uptime_seconds?: number
}

export type ModelInfoResponse = {
  architecture?: string
  security_backend?: 'self_governance' | 'legacy'
  security_model?: string
  banking_model?: string
  layers?: { name: string; model?: string; patterns?: number; latency_ms?: string }[]
}

export type SessionTimelinePoint = {
  ts: string
  cumulative_risk_score: number
}

export type SessionTimeline = {
  session_id: string
  points: SessionTimelinePoint[]
}

export type ChatRequest = {
  message: string
  session_id?: string
}

export type ChatResponse = {
  ok: boolean
  response: string
  is_safe?: boolean | null
  risk_level?: string | null
  attack_types?: string[] | null
  explanation?: string | null
  cumulative_risk_score?: number | null
  action?: string | null
  inference_ms?: number | null
  scope?: string | null
  intent?: string | null
  used_template?: boolean | null
  // agentic
  reasoning_chain?: string[] | null
  node_path?: string[] | null
  incident_path?: string | null
  novel_attack_logged?: boolean | null
  // banking knowledge agent
  response_type?: string | null
  urgency?: boolean | null
  follow_up_suggestions?: string[] | null
  requires_branch_visit?: boolean | null
  helpline_recommended?: boolean | null
  sources?: string[] | null
}
