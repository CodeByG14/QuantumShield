import type { ScanStatus } from '@/types/api'

interface BadgeProps {
  children: React.ReactNode
  variant?: 'default' | 'success' | 'warning' | 'error' | 'info'
  className?: string
}

export function Badge({ children, variant = 'default', className = '' }: BadgeProps) {
  const variantClasses = {
    default: 'bg-dark-tertiary text-text-0',
    success: 'bg-green-900 bg-opacity-50 text-green-300 border border-green-700',
    warning: 'bg-yellow-900 bg-opacity-50 text-yellow-300 border border-yellow-700',
    error: 'bg-red-900 bg-opacity-50 text-red-300 border border-red-700',
    info: 'bg-blue-900 bg-opacity-50 text-blue-300 border border-blue-700',
  }

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${variantClasses[variant]} ${className}`}
    >
      {children}
    </span>
  )
}

interface StatusBadgeProps {
  status: ScanStatus
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const statusConfig: Record<ScanStatus, { variant: BadgeProps['variant']; label: string }> = {
    queued: { variant: 'info', label: 'Queued' },
    running: { variant: 'warning', label: 'Running' },
    completed: { variant: 'success', label: 'Completed' },
    failed: { variant: 'error', label: 'Failed' },
    cancelled: { variant: 'default', label: 'Cancelled' },
  }

  const config = statusConfig[status]

  return (
    <Badge variant={config.variant}>
      <span className="flex items-center gap-1">
        {status === 'running' && (
          <span className="inline-block h-2 w-2 rounded-full bg-yellow-400 animate-pulse" />
        )}
        {config.label}
      </span>
    </Badge>
  )
}
