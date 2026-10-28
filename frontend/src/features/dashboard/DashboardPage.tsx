import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/api-errors'
import { formatRelativeTime } from '@/lib/formatters'
import type { ProjectOut, ScanStatusOut } from '@/types/api'
import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Loading } from '@/components/ui/Loading'
import { ErrorMessage } from '@/components/ui/ErrorMessage'
import { EmptyState } from '@/components/ui/EmptyState'
import { StatusBadge } from '@/components/ui/Badge'
import type { DashboardSummary } from '@/types/api'

export function DashboardPage() {
  const navigate = useNavigate()
  const [projects, setProjects] = useState<ProjectOut[]>([])
  const [recentScans, setRecentScans] = useState<ScanStatusOut[]>([])
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadDashboardData()
  }, [])

  async function loadDashboardData() {
    try {
      setLoading(true)
      setError(null)

      const [projectsData, summaryData] = await Promise.all([
        api.listProjects(),
        api.getDashboardSummary(),
      ])
      setProjects(projectsData)
      setSummary(summaryData)

      const scanLists = await Promise.all(
        projectsData.slice(0, 5).map((project) =>
          api.listProjectScans(project.project_id, 5, 0)
        )
      )
      const allScans = scanLists.flatMap((scanList) => scanList.items)

      const sortedScans = allScans.sort(
        (a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime()
      )
      setRecentScans(sortedScans.slice(0, 5))
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <Loading fullScreen text="Loading dashboard..." />
  }

  if (error || !summary) {
    return (
      <ErrorMessage
        title="Failed to Load Dashboard"
        message={error || 'The dashboard summary was unavailable.'}
        onRetry={loadDashboardData}
        fullScreen
      />
    )
  }

  const hasProjects = projects.length > 0
  const hasScans = recentScans.length > 0
  const queuedScans = summary.scans_by_status.queued ?? 0
  const runningScans = summary.scans_by_status.running ?? 0
  const completedScans = summary.scans_by_status.completed ?? 0
  const failedScans = summary.scans_by_status.failed ?? 0
  const highRiskItems = summary.latest_assessment_risk_levels.high ?? 0
  const veryHighRiskItems = summary.latest_assessment_risk_levels['very-high'] ?? 0
  const criticalRiskItems = summary.latest_assessment_risk_levels.critical ?? 0

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description="Overview of your quantum cryptography migration projects"
        action={
          <Button variant="primary" onClick={() => navigate('/scans/new')}>
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            New Scan
          </Button>
        }
      />

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-4">
        <Card>
          <CardBody>
            <p className="text-sm text-text-2 mb-2">Projects</p>
            <p className="text-3xl font-bold text-text-0">{summary.project_count}</p>
            <p className="text-xs text-text-3 mt-2">In this local session</p>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <p className="text-sm text-text-2 mb-2">All-Time Scans</p>
            <p className="text-3xl font-bold text-text-0">{summary.scan_count}</p>
            <p className="text-xs text-text-3 mt-2">
              {completedScans} completed · {failedScans} failed
            </p>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <p className="text-sm text-text-2 mb-2">Active Scans</p>
            <p className="text-3xl font-bold text-text-0">{summary.active_scan_count}</p>
            <p className="text-xs text-text-3 mt-2">
              {queuedScans} queued · {runningScans} running
            </p>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <p className="text-sm text-text-2 mb-2">High-Priority Risk Items</p>
            <p className="text-3xl font-bold text-text-0">{summary.high_priority_risk_count}</p>
            <p className="text-xs text-text-3 mt-2">
              {highRiskItems} high · {veryHighRiskItems} very high · {criticalRiskItems} critical
            </p>
          </CardBody>
        </Card>
      </div>
      <p className="text-xs text-text-3 mb-8">
        Risk figures use each project’s latest completed assessment ({summary.latest_assessment_count} included),
        may include potential or provisional findings, and indicate migration priority—not proof of exploitability
        or security. Imported SBOM/CBOM results do not represent a source-code rescan.
      </p>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Projects */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-text-0">Recent Projects</h2>
              <Button variant="ghost" size="sm" onClick={() => navigate('/projects')}>
                View All →
              </Button>
            </div>
          </CardHeader>
          <CardBody className="p-0">
            {!hasProjects ? (
              <EmptyState
                title="No Projects Yet"
                description="Create your first project to start scanning for quantum-vulnerable cryptography"
                action={{
                  label: 'Create Project',
                  onClick: () => navigate('/projects'),
                }}
              />
            ) : (
              <div className="divide-y divide-neutral-100">
                {projects.slice(0, 5).map((project) => (
                  <div
                    key={project.project_id}
                    className="px-6 py-4 hover:bg-dark-tertiary cursor-pointer transition-colors"
                    onClick={() => navigate(`/projects/${project.project_id}`)}
                  >
                    <h3 className="font-medium text-text-0">{project.project_name}</h3>
                    <p className="text-sm text-text-3 mt-1">
                      {project.description || 'No description'}
                    </p>
                    <p className="text-xs text-text-3 mt-2">
                      Updated {formatRelativeTime(project.updated_at)}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>

        {/* Recent Scans */}
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-text-0">Recent Scans</h2>
          </CardHeader>
          <CardBody className="p-0">
            {!hasScans ? (
              <EmptyState
                title="No Scans Yet"
                description="Start a scan to analyze cryptographic usage in your projects"
                action={{
                  label: 'New Scan',
                  onClick: () => navigate('/scans/new'),
                }}
              />
            ) : (
              <div className="divide-y divide-neutral-100">
                {recentScans.map((scan) => (
                  <div
                    key={scan.scan_run_id}
                    className="px-6 py-4 hover:bg-dark-tertiary cursor-pointer transition-colors"
                    onClick={() => navigate(`/scans/${scan.scan_run_id}`)}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <h3 className="font-medium text-text-0 truncate">
                          {scan.input_name || 'Unnamed scan'}
                        </h3>
                        <p className="text-xs text-text-3 mt-1">
                          {scan.input_kind} • {formatRelativeTime(scan.started_at)}
                        </p>
                      </div>
                      <StatusBadge status={scan.status} />
                    </div>
                    {scan.error_message && (
                      <p className="text-sm text-brand-primary mt-2">{scan.error_message}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
