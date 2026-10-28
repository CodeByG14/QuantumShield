import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/api-errors'
import { formatRelativeTime } from '@/lib/formatters'
import type { ProjectOut, ProjectCreate } from '@/types/api'
import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody } from '@/components/ui/Card'
import { Loading } from '@/components/ui/Loading'
import { ErrorMessage } from '@/components/ui/ErrorMessage'
import { EmptyState } from '@/components/ui/EmptyState'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'

export function ProjectsListPage() {
  const navigate = useNavigate()
  const [projects, setProjects] = useState<ProjectOut[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [projectToDelete, setProjectToDelete] = useState<ProjectOut | null>(null)

  useEffect(() => {
    loadProjects()
  }, [])

  async function loadProjects() {
    try {
      setLoading(true)
      setError(null)
      const data = await api.listProjects()
      setProjects(data)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  function handleDeleteClick(project: ProjectOut, e: React.MouseEvent) {
    e.stopPropagation() // Prevent navigation to project detail
    setProjectToDelete(project)
  }

  function handleDeleteConfirm() {
    if (!projectToDelete) return
    
    // Remove from UI (frontend-only delete)
    setProjects(projects.filter(p => p.project_id !== projectToDelete.project_id))
    setProjectToDelete(null)
    
    // Note: Backend doesn't have DELETE endpoint, so we only remove from UI
    // Database cleanup will be done manually later
  }

  function handleDeleteCancel() {
    setProjectToDelete(null)
  }

  if (loading) {
    return <Loading fullScreen text="Loading projects..." />
  }

  if (error) {
    return (
      <ErrorMessage
        title="Failed to Load Projects"
        message={error}
        onRetry={loadProjects}
        fullScreen
      />
    )
  }

  return (
    <div>
      <PageHeader
        title="Projects"
        description="Manage your quantum cryptography migration projects"
        action={
          !showCreateForm && (
            <Button variant="primary" onClick={() => setShowCreateForm(true)}>
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              New Project
            </Button>
          )
        }
      />

      {showCreateForm && (
        <Card className="mb-6">
          <CardBody>
            <CreateProjectForm
              onSuccess={(project) => {
                setProjects([project, ...projects])
                setShowCreateForm(false)
              }}
              onCancel={() => setShowCreateForm(false)}
            />
          </CardBody>
        </Card>
      )}

      {/* Delete Confirmation Modal */}
      {projectToDelete && (
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
                    Are you sure you want to delete <span className="font-semibold">"{projectToDelete.project_name}"</span>?
                  </p>
                  <p className="text-sm text-text-3">
                    This will remove the project from your view. All associated scans and data will remain in the database.
                  </p>
                </div>
              </div>
              
              <div className="flex gap-3 justify-end">
                <Button variant="outline" onClick={handleDeleteCancel}>
                  Cancel
                </Button>
                <Button variant="danger" onClick={handleDeleteConfirm}>
                  Delete Project
                </Button>
              </div>
            </CardBody>
          </Card>
        </div>
      )}

      {projects.length === 0 && !showCreateForm ? (
        <EmptyState
          icon={
            <svg className="mx-auto h-12 w-12 text-neutral-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
            </svg>
          }
          title="No Projects Yet"
          description="Create your first project to organize your cryptography scans and assessments"
          action={{
            label: 'Create Project',
            onClick: () => setShowCreateForm(true),
          }}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <Card
              key={project.project_id}
              hover
              onClick={() => navigate(`/projects/${project.project_id}`)}
            >
              <CardBody>
                <div className="flex items-start justify-between mb-2">
                  <h3 className="text-lg font-semibold text-text-0 flex-1">
                    {project.project_name}
                  </h3>
                  <button
                    onClick={(e) => handleDeleteClick(project, e)}
                    className="text-text-3 hover:text-brand-primary transition-colors ml-2 p-1 rounded hover:bg-red-900 hover:bg-opacity-30"
                    aria-label="Delete project"
                    title="Delete project"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </div>
                <p className="text-sm text-text-2 mb-4 line-clamp-2">
                  {project.description || 'No description provided'}
                </p>
                <div className="flex items-center justify-between text-xs text-text-3">
                  <span>Created {formatRelativeTime(project.created_at)}</span>
                  <span>Updated {formatRelativeTime(project.updated_at)}</span>
                </div>
              </CardBody>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}

interface CreateProjectFormProps {
  onSuccess: (project: ProjectOut) => void
  onCancel: () => void
}

function CreateProjectForm({ onSuccess, onCancel }: CreateProjectFormProps) {
  const [formData, setFormData] = useState<ProjectCreate>({
    project_name: '',
    description: null,
  })
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function validateForm(): boolean {
    const newErrors: Record<string, string> = {}

    if (!formData.project_name.trim()) {
      newErrors.project_name = 'Project name is required'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()

    if (!validateForm()) return

    try {
      setSubmitting(true)
      setError(null)
      const project = await api.createProject(formData)
      onSuccess(project)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <h3 className="text-lg font-semibold text-text-0 mb-4">Create New Project</h3>

      <div className="space-y-4 mb-4">
        <Input
          label="Project Name"
          value={formData.project_name}
          onChange={(e) =>
            setFormData({ ...formData, project_name: e.target.value })
          }
          error={errors.project_name}
          required
          maxLength={255}
          placeholder="e.g., Legacy Banking System Migration"
        />

        <Textarea
          label="Description (Optional)"
          value={formData.description || ''}
          onChange={(e) =>
            setFormData({
              ...formData,
              description: e.target.value || null,
            })
          }
          error={errors.description}
          maxLength={5000}
          placeholder="Describe the project scope and objectives..."
        />
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-900 bg-opacity-20 border border-brand-primary rounded-md text-sm text-brand-primary" role="alert">
          {error}
        </div>
      )}

      <div className="flex gap-3 justify-end">
        <Button variant="outline" onClick={onCancel} disabled={submitting}>
          Cancel
        </Button>
        <Button variant="primary" type="submit" isLoading={submitting}>
          Create Project
        </Button>
      </div>
    </form>
  )
}
