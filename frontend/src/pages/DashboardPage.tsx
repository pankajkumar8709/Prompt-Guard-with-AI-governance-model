import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Line, Pie, Bar } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'
import { useNavigate } from 'react-router-dom'
import { Shield, Activity, AlertTriangle, CheckCircle, TrendingUp, Zap, Server, Clock, Wifi, WifiOff, MessageSquare } from 'lucide-react'
import { getStats, getDistribution, getTimeseries, getAttackTypes, getLiveFeed, getTenants, getHealth, getModelInfo } from '../lib/api'
import { CustomCursor } from '../components/ui/CustomCursor'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler
)

function AnimatedNumber({ value, duration = 1000 }: { value: number; duration?: number }) {
  const [displayValue, setDisplayValue] = useState(0)
  
  useEffect(() => {
    let startTime: number
    let animationFrame: number
    
    const animate = (currentTime: number) => {
      if (!startTime) startTime = currentTime
      const progress = Math.min((currentTime - startTime) / duration, 1)
      
      const easeOutCubic = 1 - Math.pow(1 - progress, 3)
      setDisplayValue(Math.floor(easeOutCubic * value))
      
      if (progress < 1) {
        animationFrame = requestAnimationFrame(animate)
      }
    }
    
    animationFrame = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(animationFrame)
  }, [value, duration])
  
  return <span>{displayValue.toLocaleString()}</span>
}

function MetricCard({ icon: Icon, label, value, trend, color }: any) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass rounded-2xl p-6 hover-lift spring-transition"
    >
      <div className="flex items-start justify-between mb-4">
        <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${color} flex items-center justify-center glow-${color.includes('cyan') ? 'cyan' : color.includes('violet') ? 'violet' : 'red'}`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
        {trend && (
          <div className="flex items-center gap-1 text-xs text-green-400">
            <TrendingUp className="w-3 h-3" />
            {trend}
          </div>
        )}
      </div>
      <div className="text-3xl font-bold text-foreground mb-1 count-up">
        <AnimatedNumber value={value} />
      </div>
      <div className="text-sm text-muted">{label}</div>
    </motion.div>
  )
}

function LiveFeedTicker({ rows }: { rows: any[] }) {
  return (
    <div className="glass rounded-2xl p-4 overflow-hidden">
      <div className="flex items-center gap-2 mb-3">
        <Activity className="w-4 h-4 text-cyan-400" />
        <span className="text-sm font-semibold text-foreground">Live Threat Feed</span>
      </div>
      <div className="relative h-8 overflow-hidden">
        <motion.div
          className="flex gap-4 absolute"
          animate={{ x: [0, -1000] }}
          transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
        >
          {[...rows, ...rows].map((row, idx) => (
            <div key={idx} className="flex items-center gap-2 px-4 py-1 rounded-lg glass-light border border-border whitespace-nowrap">
              <span className={`w-2 h-2 rounded-full ${
                row.risk_level === 'MALICIOUS' ? 'bg-red-500' :
                row.risk_level === 'SUSPICIOUS' ? 'bg-yellow-500' :
                'bg-green-500'
              } pulse-glow`} />
              <span className="text-xs text-muted font-mono">{row.ts?.slice(11, 19)}</span>
              <span className="text-xs text-foreground">{row.tenant_id}</span>
              <span className={`text-xs font-bold ${
                row.risk_level === 'MALICIOUS' ? 'text-red-400' :
                row.risk_level === 'SUSPICIOUS' ? 'text-yellow-400' :
                'text-green-400'
              }`}>
                {row.enforcement_action}
              </span>
            </div>
          ))}
        </motion.div>
      </div>
    </div>
  )
}

const DISTRIBUTION_COLORS: Record<string, string> = {
  SAFE: '#10B981',
  BENIGN: '#10B981',
  IN_SCOPE: '#10B981',
  REQUIRES_AUTH: '#F59E0B',
  OUT_OF_SCOPE: '#3B82F6',
  MALICIOUS: '#EF4444',
  JAILBREAK: '#EF4444',
  INJECTION: '#F59E0B',
}

const ATTACK_TYPE_LABELS: Record<string, string> = {
  JAILBREAK: 'Jailbreak',
  SYSTEM_PROMPT_OVERRIDE: 'System Override',
  DATA_EXTRACTION: 'Data Extraction',
  INSTRUCTION_CHAINING: 'Instruction Chain',
  SOCIAL_ENGINEERING: 'Social Engineering',
  FAST_RULE: 'Fast Rule',
  NONE: 'None',
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  if (m < 60) return `${m}m ${s}s`
  const h = Math.floor(m / 60)
  const min = m % 60
  return `${h}h ${min}m`
}

export function DashboardPage() {
  const navigate = useNavigate()
  const [tenant, setTenant] = useState('all')
  
  const tenantsQ = useQuery({ queryKey: ['tenants'], queryFn: getTenants })
  const healthQ = useQuery({ queryKey: ['health'], queryFn: getHealth, refetchInterval: 10000 })
  const modelQ = useQuery({ queryKey: ['model'], queryFn: getModelInfo, refetchInterval: 30000 })
  const statsQ = useQuery({ 
    queryKey: ['stats', tenant], 
    queryFn: () => getStats(tenant === 'all' ? undefined : tenant),
    refetchInterval: 5000
  })
  const distQ = useQuery({ 
    queryKey: ['distribution', tenant], 
    queryFn: () => getDistribution(tenant === 'all' ? undefined : tenant),
    refetchInterval: 5000
  })
  const timeseriesQ = useQuery({ 
    queryKey: ['timeseries', tenant], 
    queryFn: () => getTimeseries(tenant === 'all' ? undefined : tenant),
    refetchInterval: 5000
  })
  const attacksQ = useQuery({ 
    queryKey: ['attacks', tenant], 
    queryFn: () => getAttackTypes(tenant === 'all' ? undefined : tenant),
    refetchInterval: 5000
  })
  const liveQ = useQuery({ 
    queryKey: ['live', tenant], 
    queryFn: () => getLiveFeed(tenant === 'all' ? undefined : tenant),
    refetchInterval: 2000
  })

  const stats = statsQ.data || { total_requests: 0, blocked: 0, warned: 0, whitelist_hits: 0, hard_block_hits: 0 }
  const dist = distQ.data || {}
  const timeseries = timeseriesQ.data?.points || []
  const attacks = attacksQ.data || {}
  const live = liveQ.data?.rows || []
  const health = healthQ.data
  const modelInfo = modelQ.data
  const backendDown = healthQ.isError || statsQ.isError

  const lineData = {
    labels: timeseries.map(p => p.hour?.slice(11, 16) || ''),
    datasets: [{
      label: 'Requests',
      data: timeseries.map(p => p.count),
      borderColor: '#00D4FF',
      backgroundColor: 'rgba(0, 212, 255, 0.1)',
      fill: true,
      tension: 0.4,
      pointRadius: 4,
      pointHoverRadius: 6,
      pointBackgroundColor: '#00D4FF',
      pointBorderColor: '#0A0B0F',
      pointBorderWidth: 2,
    }]
  }

  const distKeys = Object.keys(dist).filter(k => Number(dist[k]) > 0)
  if (distKeys.length === 0) distKeys.push('SAFE', 'MALICIOUS')
  const pieData = {
    labels: distKeys,
    datasets: [{
      data: distKeys.map(k => Number(dist[k]) || 0),
      backgroundColor: distKeys.map(k => DISTRIBUTION_COLORS[k] || '#6B7280'),
      borderColor: '#0A0B0F',
      borderWidth: 2,
    }]
  }

  const attackKeys = Object.keys(attacks).filter(k => k !== 'NONE' && Number(attacks[k]) > 0)
  const barLabels = attackKeys.length > 0 ? attackKeys : ['JAILBREAK', 'DATA_EXTRACTION', 'SYSTEM_PROMPT_OVERRIDE']
  const barData = {
    labels: barLabels.map(k => ATTACK_TYPE_LABELS[k] || k),
    datasets: [{
      label: 'Detections',
      data: barLabels.map(k => Number(attacks[k]) || 0),
      backgroundColor: ['#EF4444', '#F59E0B', '#EC4899', '#A855F7', '#10B981', '#3B82F6'].slice(0, barLabels.length),
      borderRadius: 8,
    }]
  }

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#111318',
        titleColor: '#E5E7EB',
        bodyColor: '#9CA3AF',
        borderColor: '#1E2028',
        borderWidth: 1,
        padding: 12,
        displayColors: false,
      }
    },
    scales: {
      x: {
        grid: { color: '#1E2028', drawBorder: false },
        ticks: { color: '#9CA3AF', font: { size: 11 } }
      },
      y: {
        grid: { color: '#1E2028', drawBorder: false },
        ticks: { color: '#9CA3AF', font: { size: 11 } }
      }
    }
  }

  return (
    <div className="min-h-screen particle-bg">
      <CustomCursor />
      <div className="grain-overlay" />
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-screen w-20 glass border-r border-border flex flex-col items-center py-8 gap-6 z-50">
        <motion.button
          type="button"
          onClick={() => navigate('/')}
          className="w-12 h-12 rounded-2xl bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center glow-cyan cursor-pointer"
          whileHover={{ scale: 1.1, rotate: 5 }}
          whileTap={{ scale: 0.98 }}
          title="Home"
        >
          <Shield className="w-6 h-6 text-white" />
        </motion.button>
      </aside>

      {/* Main Content */}
      <main className="ml-20 p-8">
        <div className="max-w-7xl mx-auto space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-violet-500 bg-clip-text text-transparent mb-2">
                Prompt-Guard Dashboard
              </h1>
              <p className="text-sm text-muted">Real-time security monitoring and analytics</p>
            </div>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => navigate('/chat')}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl glass border border-border hover:border-cyan-500/50 text-sm font-medium text-foreground spring-transition"
              >
                <MessageSquare className="w-4 h-4 text-cyan-400" />
                Open Chat
              </button>
              <select
                className="glass border border-border rounded-xl px-4 py-2.5 text-sm text-foreground focus:border-cyan-500/50 focus:outline-none spring-transition"
                value={tenant}
                onChange={(e) => setTenant(e.target.value)}
              >
                <option value="all">All Tenants</option>
                {(tenantsQ.data?.tenants || []).map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Hackathon status strip: backend, uptime, health */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex flex-wrap items-center gap-4 py-3 px-4 rounded-xl glass border border-border"
          >
            {backendDown ? (
              <div className="flex items-center gap-2 text-amber-400">
                <WifiOff className="w-4 h-4" />
                <span className="text-sm font-medium">Backend unreachable — check API URL and server</span>
              </div>
            ) : (
              <>
                <div className="flex items-center gap-2 text-foreground">
                  <Wifi className="w-4 h-4 text-green-400" />
                  <span className="text-sm font-medium">Status</span>
                  <span className="text-sm text-green-400">{health?.status ?? '—'}</span>
                </div>
                <div className="flex items-center gap-2 text-foreground">
                  <Server className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm font-medium">Security backend</span>
                  <span className="text-sm px-2 py-0.5 rounded-md bg-cyan-500/20 text-cyan-400 font-mono">
                    {health?.security_backend ?? modelInfo?.security_backend ?? '—'}
                  </span>
                </div>
                {health?.uptime_seconds != null && (
                  <div className="flex items-center gap-2 text-foreground">
                    <Clock className="w-4 h-4 text-violet-400" />
                    <span className="text-sm font-medium">Uptime</span>
                    <span className="text-sm text-muted font-mono">{formatUptime(health.uptime_seconds)}</span>
                  </div>
                )}
                {modelInfo?.security_model && (
                  <div className="text-xs text-muted">
                    Model: {modelInfo.security_model}
                  </div>
                )}
              </>
            )}
          </motion.div>

          {/* Live Feed Ticker */}
          {live.length > 0 && <LiveFeedTicker rows={live} />}

          {/* Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <MetricCard
              icon={Activity}
              label="Total Requests"
              value={stats.total_requests}
              color="from-cyan-500 to-blue-600"
            />
            <MetricCard
              icon={AlertTriangle}
              label="Blocked"
              value={stats.blocked}
              color="from-red-500 to-pink-600"
            />
            <MetricCard
              icon={CheckCircle}
              label="Whitelist Hits"
              value={stats.whitelist_hits}
              color="from-green-500 to-emerald-600"
            />
            <MetricCard
              icon={Zap}
              label="Hard Blocks"
              value={stats.hard_block_hits}
              color="from-violet-500 to-purple-600"
            />
          </div>

          {/* Charts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Line Chart */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="lg:col-span-2 glass rounded-2xl p-6 hover-lift spring-transition"
            >
              <h3 className="text-sm font-semibold text-foreground mb-4">Requests per Hour (24h)</h3>
              <div className="h-64">
                {timeseriesQ.isLoading ? (
                  <div className="h-full flex items-center justify-center">
                    <div className="skeleton w-full h-full rounded-xl" />
                  </div>
                ) : (
                  <Line data={lineData} options={chartOptions} />
                )}
              </div>
            </motion.div>

            {/* Pie Chart */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="glass rounded-2xl p-6 hover-lift spring-transition"
            >
              <h3 className="text-sm font-semibold text-foreground mb-4">Label Distribution</h3>
              <div className="h-64">
                {distQ.isLoading ? (
                  <div className="h-full flex items-center justify-center">
                    <div className="skeleton w-full h-full rounded-full" />
                  </div>
                ) : (
                  <Pie data={pieData} options={{ ...chartOptions, scales: undefined }} />
                )}
              </div>
            </motion.div>
          </div>

          {/* Attack Breakdown */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="glass rounded-2xl p-6 hover-lift spring-transition"
          >
            <h3 className="text-sm font-semibold text-foreground mb-4">Attack Type Breakdown</h3>
            <div className="h-64">
              {attacksQ.isLoading ? (
                <div className="h-full flex items-center justify-center">
                  <div className="skeleton w-full h-full rounded-xl" />
                </div>
              ) : (
                <Bar data={barData} options={chartOptions} />
              )}
            </div>
          </motion.div>

          {/* Live Feed Table */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="glass rounded-2xl p-6"
          >
            <h3 className="text-sm font-semibold text-foreground mb-4">Recent Activity</h3>
            <div className="overflow-x-auto scrollbar-custom">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left py-3 px-4 text-muted font-semibold">Time</th>
                    <th className="text-left py-3 px-4 text-muted font-semibold">Tenant</th>
                    <th className="text-left py-3 px-4 text-muted font-semibold">Risk</th>
                    <th className="text-left py-3 px-4 text-muted font-semibold">Action</th>
                    <th className="text-left py-3 px-4 text-muted font-semibold">Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {live.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-12 text-center text-muted text-sm">
                        No requests yet. Send messages from the Chat page to see live activity here.
                      </td>
                    </tr>
                  ) : (
                    live.slice(0, 10).map((row, idx) => (
                      <motion.tr
                        key={idx}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.05 }}
                        className="border-b border-border/50 hover:bg-surface-light spring-transition"
                      >
                        <td className="py-3 px-4 font-mono text-muted">{row.ts?.slice(11, 19)}</td>
                        <td className="py-3 px-4 text-foreground">{row.tenant_id}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-1 rounded-md text-xs font-bold ${
                            row.risk_level === 'MALICIOUS' ? 'bg-red-500/20 text-red-400' :
                            row.risk_level === 'SUSPICIOUS' ? 'bg-yellow-500/20 text-yellow-400' :
                            (row.risk_level === 'SAFE' || row.label === 'SAFE') ? 'bg-green-500/20 text-green-400' :
                            'bg-cyan-500/20 text-cyan-400'
                          }`}>
                            {row.risk_level ?? row.label ?? '—'}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-foreground font-semibold">{row.enforcement_action ?? '—'}</td>
                        <td className="py-3 px-4 font-mono text-cyan-400">{row.inference_ms != null ? `${Math.round(Number(row.inference_ms))}ms` : '—'}</td>
                      </motion.tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </motion.div>
        </div>
      </main>
    </div>
  )
}
