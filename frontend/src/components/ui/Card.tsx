import type { ReactNode } from 'react'
import clsx from 'clsx'

export function Card({
  className,
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return (
    <div
      className={clsx(
        'rounded-2xl border border-slate-200 bg-white shadow-soft',
        className,
      )}
    >
      {children}
    </div>
  )
}

export function CardHeader({
  className,
  title,
  subtitle,
  right,
}: {
  className?: string
  title: string
  subtitle?: string
  right?: ReactNode
}) {
  return (
    <div className={clsx('flex items-start justify-between gap-4 p-5', className)}>
      <div>
        <div className="text-sm font-semibold text-slate-900">{title}</div>
        {subtitle ? (
          <div className="mt-1 text-xs text-slate-500">{subtitle}</div>
        ) : null}
      </div>
      {right ? <div className="shrink-0">{right}</div> : null}
    </div>
  )
}

export function CardBody({
  className,
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return <div className={clsx('px-5 pb-5', className)}>{children}</div>
}
