import { NavLink } from 'react-router-dom'
import clsx from 'clsx'
import { LayoutDashboard, MessagesSquare } from 'lucide-react'

function Brand() {
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 text-white shadow-soft">
        PG
      </div>
      <div className="leading-tight">
        <div className="text-sm font-extrabold tracking-tight text-slate-900">Prompt-Guard</div>
        <div className="text-[11px] text-slate-500">Safe LLM Gateway</div>
      </div>
    </div>
  )
}

function SideLink({
  to,
  icon,
  label,
}: {
  to: string
  icon: React.ReactNode
  label: string
}) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        clsx(
          'flex items-center gap-2 rounded-xl px-3 py-2 text-sm font-semibold transition',
          isActive
            ? 'bg-brand-50 text-brand-700 ring-1 ring-brand-100'
            : 'text-slate-700 hover:bg-slate-100',
        )
      }
      end
    >
      <span className="text-slate-500">{icon}</span>
      {label}
    </NavLink>
  )
}

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-50">
      <div className="mx-auto flex w-full max-w-7xl gap-6 px-4 py-6">
        <aside className="hidden w-64 shrink-0 lg:block">
          <div className="sticky top-6 space-y-4">
            <Brand />
            <nav className="space-y-1">
              <SideLink to="/" icon={<LayoutDashboard size={18} />} label="Dashboard" />
              <SideLink to="/chat" icon={<MessagesSquare size={18} />} label="Chat" />
            </nav>
            <div className="rounded-2xl border border-slate-200 bg-white p-4 text-xs text-slate-600 shadow-soft">
              <div className="font-semibold text-slate-900">Backend</div>
              <div className="mt-1">Default: http://127.0.0.1:8000</div>
              <div className="mt-2 text-[11px] text-slate-500">
                Configure via <code className="rounded bg-slate-100 px-1 py-0.5">VITE_API_BASE_URL</code>
              </div>
            </div>
          </div>
        </aside>

        <main className="min-w-0 flex-1">{children}</main>
      </div>
    </div>
  )
}
