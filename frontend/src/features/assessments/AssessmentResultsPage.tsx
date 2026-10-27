import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { api } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/api-errors'
import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Loading } from '@/components/ui/Loading'
import { ErrorMessage } from '@/components/ui/ErrorMessage'

export function AssessmentResultsPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const [assessment, setAssessment] = useState<Record<string, any> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!scanId) {
      setError('No scan ID provided')
      setLoading(false)
      return
    }

    loadAssessment()
  }, [scanId])

  async function loadAssessment() {
    if (!scanId) return

    try {
      setLoading(true)
      setError(null)
      const data = await api.getScanAssessment(scanId)
      setAssessment(data)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <Loading fullScreen text="Loading assessment..." />
  }

  if (error || !assessment) {
    return (
      <ErrorMessage
        title="Failed to Load Assessment"
        message={error || 'Assessment not found'}
        onRetry={loadAssessment}
        fullScreen
      />
    )
  }

  const assessmentId = assessment.assessment_id || 'unknown'

  return (
    <div>
      <PageHeader
        title="Assessment Results"
        description={`Full assessment data for scan ${scanId}`}
        action={
          <div className="flex gap-3">
            <Button
              variant="outline"
              onClick={() => navigate(`/assessments/${assessmentId}/findings`)}
            >
              View Findings
            </Button>
            <Button
              variant="primary"
              onClick={() => navigate(`/assessments/${assessmentId}/reports`)}
            >
              Generate Reports
            </Button>
          </div>
        }
      />

      <div className="space-y-6 max-w-6xl">
        {/* Assessment Metadata */}
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-text-0">Assessment Metadata</h2>
          </CardHeader>
          <CardBody>
            <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <dt className="text-sm text-text-3 mb-1">Assessment ID</dt>
                <dd className="text-sm font-mono text-text-0">{assessmentId}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Schema Version</dt>
                <dd className="text-sm text-text-0">{assessment.schema_version || 'N/A'}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Policy Version</dt>
                <dd className="text-sm text-text-0">{assessment.policy_version || 'N/A'}</dd>
              </div>
              {assessment.target && (
                <div>
                  <dt className="text-sm text-text-3 mb-1">Target</dt>
                  <dd className="text-sm text-text-0">{assessment.target}</dd>
                </div>
              )}
            </dl>
          </CardBody>
        </Card>

        {/* Summary */}
        {assessment.summary && (
          <Card>
            <CardHeader>
              <h2 className="text-lg font-semibold text-text-0">Summary</h2>
            </CardHeader>
            <CardBody>
              <pre className="text-sm text-text-0 bg-dark-primary p-4 rounded overflow-x-auto max-h-96 border border-dark-tertiary">
                {JSON.stringify(assessment.summary, null, 2)}
              </pre>
            </CardBody>
          </Card>
        )}

        {/* Full Assessment Data */}
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-text-0">Complete Assessment Data</h2>
          </CardHeader>
          <CardBody>
            <div className="mb-4 p-3 bg-yellow-900 bg-opacity-20 border border-yellow-700 rounded-md text-sm text-yellow-300">
              <p className="font-medium">Technical Data</p>
              <p className="mt-1">This is the raw assessment output from the analysis engine. Use the Findings view for a more user-friendly interface.</p>
            </div>
            <pre className="text-xs text-text-0 bg-dark-primary p-4 rounded overflow-x-auto max-h-[600px] border border-dark-tertiary">
              {JSON.stringify(assessment, null, 2)}
            </pre>
          </CardBody>
        </Card>

        {/* Quick Actions */}
        <Card>
          <CardBody>
            <div className="flex flex-wrap gap-3">
              <Link to={`/assessments/${assessmentId}/findings`}>
                <Button variant="outline">
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  View Findings
                </Button>
              </Link>
              <Link to={`/assessments/${assessmentId}/reports`}>
                <Button variant="outline">
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Generate Reports
                </Button>
              </Link>
              <Button
                variant="ghost"
                onClick={() => {
                  const blob = new Blob([JSON.stringify(assessment, null, 2)], {
                    type: 'application/json',
                  })
                  const url = URL.createObjectURL(blob)
                  const a = document.createElement('a')
                  a.href = url
                  a.download = `assessment-${assessmentId}.json`
                  a.click()
                  URL.revokeObjectURL(url)
                }}
              >
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Download JSON
              </Button>
            </div>
          </CardBody>
        </Card>

        {/* Back Navigation */}
        <div>
          <Button variant="ghost" onClick={() => navigate(-1)}>
            ← Back
          </Button>
        </div>
      </div>
    </div>
  )
}
