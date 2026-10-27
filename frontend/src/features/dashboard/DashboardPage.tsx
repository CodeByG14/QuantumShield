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

export function DashboardPage() {
  const navigate = useNavigate()
  const [projects, setProjects] = useState<ProjectOut[]>([])
  const [recentScans, setRecentScans] = useState<ScanStatusOut[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadDashboardData()
  }, [])

  async function loadDashboardData() {
    try {
      setLoading(true)
      setError(null)

      // Load projects
      const projectsData = await api.listProjects()
      setProjects(projectsData)

      // Load recent scans from all projects
      const allScans: ScanStatusOut[] = []
      for (const project of projectsData.slice(0, 5)) {
        try {
          const scanList = await api.listProjectScans(project.project_id, 5, 0)
          allScans.push(...scanList.items)
        } catch {
          // Skip projects that fail to load scans
        }
      }

      // Sort by started_at descending and take top 5
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

  if (error) {
    return (
      <ErrorMessage
        title="Failed to Load Dashboard"
        message={error}
        onRetry={loadDashboardData}
        fullScreen
      />
    )
  }

  const hasProjects = projects.length > 0
  const hasScans = recentScans.length > 0

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

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <Card>
          <CardBody>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-text-2 mb-1">Total Projects</p>
                <p className="text-3xl font-bold text-text-0">{projects.length}</p>
              </div>
              <div className="w-12 h-12 bg-brand-secondary bg-opacity-10 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-brand-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                </svg>
              </div>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-text-2 mb-1">Total Scans</p>
                <p className="text-3xl font-bold text-text-0">{recentScans.length}</p>
                <p className="text-xs text-text-3 mt-1">Recent activity</p>
              </div>
              <div className="w-12 h-12 bg-brand-accent bg-opacity-10 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-brand-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
              </div>
            </div>
          </CardBody>
        </Card>

        <Card hover onClick={() => navigate('/scans/new')}>
          <CardBody>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-text-2 mb-1">Start New Scan</p>
                <p className="text-sm text-brand-accent font-medium">Upload or connect source →</p>
              </div>
              <div className="w-12 h-12 bg-brand-primary bg-opacity-10 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-brand-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

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
                    className="px-6 py-4 hover:bg-neutral-500 cursor-pointer transition-colors"
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
                    className="px-6 py-4 hover:bg-neutral-500 cursor-pointer transition-colors"
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
