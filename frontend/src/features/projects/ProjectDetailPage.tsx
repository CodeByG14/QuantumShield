import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { api } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/api-errors'
import { formatDateTime, formatRelativeTime } from '@/lib/formatters'
import type { ProjectOut, ScanStatusOut } from '@/types/api'
import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Loading } from '@/components/ui/Loading'
import { ErrorMessage } from '@/components/ui/ErrorMessage'
import { EmptyState } from '@/components/ui/EmptyState'
import { StatusBadge } from '@/components/ui/Badge'

export function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()
  const [project, setProject] = useState<ProjectOut | null>(null)
  const [scans, setScans] = useState<ScanStatusOut[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showDeleteModal, setShowDeleteModal] = useState(false)

  useEffect(() => {
    if (!projectId) {
      setError('No project ID provided')
      setLoading(false)
      return
    }

    loadProject()
  }, [projectId])

  async function loadProject() {
    if (!projectId) return

    try {
      setLoading(true)
      setError(null)

      // Load project details
      const projectData = await api.getProject(projectId)
      setProject(projectData)

      // Load project scans
      const scansData = await api.listProjectScans(projectId, 50, 0)
      setScans(scansData.items)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <Loading fullScreen text="Loading project..." />
  }

  if (error || !project) {
    return (
      <ErrorMessage
        title="Failed to Load Project"
        message={error || 'Project not found'}
        onRetry={loadProject}
        fullScreen
      />
    )
  }

  return (
    <div>
      <PageHeader
        title={project.project_name}
        description={project.description || 'No description provided'}
        backAction={
          <Button variant="ghost" onClick={() => navigate('/projects')}>
            ← Back to Projects
          </Button>
        }
        action={
          <div className="flex gap-3">
            <Button
              variant="outline"
              onClick={() => setShowDeleteModal(true)}
              className="text-brand-primary hover:bg-red-900 hover:bg-opacity-20 border-brand-primary"
            >
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
              Delete Project
            </Button>
          </div>
        }
      />

      <div className="space-y-6">
        {/* Project Info */}
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-text-0">Project Details</h2>
          </CardHeader>
          <CardBody>
            <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <dt className="text-sm text-text-3 mb-1">Project ID</dt>
                <dd className="text-sm font-mono text-text-0">{project.project_id}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Created</dt>
                <dd className="text-sm text-text-0">{formatDateTime(project.created_at)}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Last Updated</dt>
                <dd className="text-sm text-text-0">{formatDateTime(project.updated_at)}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Total Scans</dt>
                <dd className="text-sm text-text-0">{scans.length}</dd>
              </div>
            </dl>
          </CardBody>
        </Card>

        {/* Scans List */}
        <Card className="overflow-hidden">
          <CardHeader>
            <h2 className="text-lg font-semibold text-text-0">Scans</h2>
          </CardHeader>
          {scans.length === 0 ? (
            <CardBody>
              <EmptyState
                title="No Scans Yet"
                description="No scans have been run for this project yet."
              />
            </CardBody>
          ) : (
            <CardBody className="p-0">
              <div className="overflow-x-auto">
                <div className="min-w-[760px] space-y-2 p-2" role="table" aria-label="Project scans">
                  <div
                    className="grid grid-cols-[2fr_1fr_1fr_1fr_1.5fr] gap-4 rounded-lg border border-dark-tertiary bg-dark-primary px-6 py-3 text-xs font-medium uppercase tracking-wider text-text-2"
                    role="row"
                  >
                    <span role="columnheader">Source</span>
                    <span role="columnheader">Type</span>
                    <span role="columnheader">Status</span>
                    <span role="columnheader">Started</span>
                    <span role="columnheader">Actions</span>
                  </div>
                  {scans.map((scan) => (
                    <div
                      key={scan.scan_run_id}
                      className="grid cursor-pointer grid-cols-[2fr_1fr_1fr_1fr_1.5fr] items-center gap-4 rounded-lg border border-dark-tertiary bg-dark-secondary px-6 py-4 transition-colors hover:bg-dark-tertiary"
                      role="row"
                      onClick={() => navigate(`/scans/${scan.scan_run_id}`)}
                    >
                      <div role="cell">
                        <div className="max-w-xs truncate text-sm font-medium text-text-0">
                          {scan.input_name || 'Unnamed'}
                        </div>
                        {scan.source_revision && (
                          <div className="mt-1 font-mono text-xs text-text-3">
                            {scan.source_revision.substring(0, 8)}
                          </div>
                        )}
                      </div>
                      <span className="text-sm text-text-1" role="cell">{scan.input_kind}</span>
                      <div role="cell"><StatusBadge status={scan.status} /></div>
                      <span
                        className="text-sm text-text-2"
                        title={formatDateTime(scan.started_at)}
                        role="cell"
                      >
                        {formatRelativeTime(scan.started_at)}
                      </span>
                      <div className="flex items-center gap-2" role="cell">
                        {scan.status === 'completed' && scan.assessment_id && (
                          <>
                            <Link
                              to={`/scans/${scan.scan_run_id}/results`}
                              className="text-sm text-brand-accent hover:underline"
                              onClick={(e) => e.stopPropagation()}
                            >
                              Results
                            </Link>
                            <span className="text-text-3">·</span>
                            <Link
                              to={`/assessments/${scan.assessment_id}/findings`}
                              className="text-sm text-brand-accent hover:underline"
                              onClick={(e) => e.stopPropagation()}
                            >
                              Findings
                            </Link>
                          </>
                        )}
                        {scan.status === 'failed' && (
                          <span className="text-sm text-brand-primary">Failed</span>
                        )}
                        {(scan.status === 'queued' || scan.status === 'running') && (
                          <span className="text-sm text-text-3">In Progress</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardBody>
          )}
        </Card>

      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <Card className="max-w-md w-full">
            <CardBody>
              <div className="flex items-start gap-3 mb-4">
                <div className="flex-shrink-0 w-10 h-10 bg-red-900 bg-opacity-30 rounded-full flex items-center justify-center">
                  <svg className="w-6 h-6 text-brand-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-text-0 mb-2">
                    Delete Project
                  </h3>
                  <p className="text-sm text-text-2 mb-1">
                    Are you sure you want to delete <span className="font-semibold">"{project.project_name}"</span>?
                  </p>
                  <p className="text-sm text-text-3 mb-2">
                    This project has {scans.length} scan{scans.length !== 1 ? 's' : ''}.
                  </p>
                  <p className="text-sm text-text-3">
                    This will navigate back to projects list. All data will remain in the database.
                  </p>
                </div>
              </div>
              
              <div className="flex gap-3 justify-end">
                <Button variant="outline" onClick={() => setShowDeleteModal(false)}>
                  Cancel
                </Button>
                <Button
                  variant="danger"
                  onClick={() => {
                    setShowDeleteModal(false)
                    navigate('/projects')
                  }}
                >
                  Delete Project
                </Button>
              </div>
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  )
}
