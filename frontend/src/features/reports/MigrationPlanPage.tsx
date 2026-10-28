import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/api-errors'
import { formatDateTime } from '@/lib/formatters'
import type { PlanOut } from '@/types/api'
import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Loading } from '@/components/ui/Loading'
import { ErrorMessage } from '@/components/ui/ErrorMessage'
import { Badge } from '@/components/ui/Badge'

export function MigrationPlanPage() {
  const { planId } = useParams<{ planId: string }>()
  const navigate = useNavigate()
  const [plan, setPlan] = useState<PlanOut | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!planId) {
      setError('No plan ID provided')
      setLoading(false)
      return
    }

    loadPlan()
  }, [planId])

  async function loadPlan() {
    if (!planId) return

    try {
      setLoading(true)
      setError(null)
      const data = await api.getPlan(planId)
      setPlan(data)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <Loading fullScreen text="Loading migration plan..." />
  }

  if (error || !plan) {
    return (
      <ErrorMessage
        title="Failed to Load Plan"
        message={error || 'Plan not found'}
        onRetry={loadPlan}
        fullScreen
      />
    )
  }

  const tasks = plan.plan.tasks || []

  return (
    <div>
      <PageHeader
        title="Migration Plan"
        description={`Plan for assessment ${plan.assessment_id}`}
        backAction={
          <Button variant="ghost" onClick={() => navigate(-1)}>
            ← Back
          </Button>
        }
        action={
          <Button
            variant="outline"
            onClick={() => {
              const blob = new Blob([JSON.stringify(plan.plan, null, 2)], {
                type: 'application/json',
              })
              const url = URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url
              a.download = `plan-${plan.migration_plan_id}.json`
              a.click()
              URL.revokeObjectURL(url)
            }}
          >
            Download JSON
          </Button>
        }
      />

      <div className="space-y-6 max-w-6xl">
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-text-0">Plan Details</h2>
          </CardHeader>
          <CardBody>
            <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <dt className="text-sm text-text-3 mb-1">Plan ID</dt>
                <dd className="text-sm font-mono text-text-0">{plan.migration_plan_id}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Assessment ID</dt>
                <dd className="text-sm font-mono text-text-0">{plan.assessment_id}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Generated</dt>
                <dd className="text-sm text-text-0">{formatDateTime(plan.generated_at)}</dd>
              </div>
            </dl>
          </CardBody>
        </Card>

        {plan.summary && Object.keys(plan.summary).length > 0 && (
          <Card>
            <CardHeader>
              <h2 className="text-lg font-semibold text-text-0">Summary</h2>
            </CardHeader>
            <CardBody>
              <pre className="text-sm text-text-1 bg-dark-primary p-4 rounded overflow-x-auto border border-dark-tertiary">
                {JSON.stringify(plan.summary, null, 2)}
              </pre>
            </CardBody>
          </Card>
        )}

        {tasks.length > 0 && (
          <Card>
            <CardHeader>
              <h2 className="text-lg font-semibold text-text-0">
                Migration Tasks ({tasks.length})
              </h2>
            </CardHeader>
            <CardBody className="p-0">
              <div className="divide-y divide-dark-tertiary">
                {tasks.map((task: any, index: number) => (
                  <div key={index} className="p-6">
                    <div className="flex items-start justify-between mb-3">
                      <h3 className="font-semibold text-text-0">
                        {task.title || `Task ${index + 1}`}
                      </h3>
                      <div className="flex gap-2">
                        {task.priority && (
                          <Badge
                            variant={
                              task.priority === 'high' ? 'error' :
                              task.priority === 'medium' ? 'warning' : 'default'
                            }
                          >
                            {task.priority}
                          </Badge>
                        )}
                      </div>
                    </div>
                    {task.description && (
                      <p className="text-sm text-text-2 mb-2">{task.description}</p>
                    )}
                    {task.rationale && (
                      <p className="text-xs text-text-3 mb-2">Rationale: {task.rationale}</p>
                    )}
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>
        )}

        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-text-0">Complete Plan</h2>
          </CardHeader>
          <CardBody>
            <pre className="text-xs text-text-1 bg-dark-primary p-4 rounded overflow-x-auto max-h-[400px] border border-dark-tertiary">
              {JSON.stringify(plan.plan, null, 2)}
            </pre>
          </CardBody>
        </Card>

      </div>
    </div>
  )
}
