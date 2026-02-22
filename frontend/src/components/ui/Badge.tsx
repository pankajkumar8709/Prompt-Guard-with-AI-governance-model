import clsx from 'clsx'
import type { ReactNode } from 'react'

export function Badge({
  children,
  variant = 'neutral',
  className,
}: {
  children: ReactNode
  variant?: 'neutral' | 'success' | 'warning' | 'danger' | 'info'
  className?: string
}) {
  const styles: Record<string, string> = {
    neutral: 'border-slate-200 bg-slate-50 text-slate-700',
    info: 'border-blue-200 bg-blue-50 text-blue-700',
    success: 'border-emerald-200 bg-emerald-50 text-emerald-700',
    warning: 'border-amber-200 bg-amber-50 text-amber-800',
    danger: 'border-rose-200 bg-rose-50 text-rose-700',
  }

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-semibold',
        styles[variant],
        className,
      )}
    >
      {children}
    </span>
  )
}
