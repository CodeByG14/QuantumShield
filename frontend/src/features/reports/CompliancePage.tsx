import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/api-errors'
import { formatDateTime } from '@/lib/formatters'
import type { ComplianceOut } from '@/types/api'
import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Loading } from '@/components/ui/Loading'
import { ErrorMessage } from '@/components/ui/ErrorMessage'

export function CompliancePage() {
  const { reportId } = useParams<{ reportId: string }>()
  const navigate = useNavigate()
  const [report, setReport] = useState<ComplianceOut | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!reportId) {
      setError('No report ID provided')
      setLoading(false)
      return
    }

    loadReport()
  }, [reportId])

  async function loadReport() {
    if (!reportId) return

    try {
      setLoading(true)
      setError(null)
      const data = await api.getCompliance(reportId)
      setReport(data)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <Loading fullScreen text="Loading compliance report..." />
  }

  if (error || !report) {
    return (
      <ErrorMessage
        title="Failed to Load Report"
        message={error || 'Report not found'}
        onRetry={loadReport}
        fullScreen
      />
    )
  }

  return (
    <div>
      <PageHeader
        title="Compliance Report"
        description={`Post-quantum cryptography compliance for ${report.assessment_id}`}
        backAction={
          <Button variant="ghost" onClick={() => navigate(-1)}>
            ← Back
          </Button>
        }
        action={
          <Button
            variant="outline"
            onClick={() => {
              const blob = new Blob([JSON.stringify(report.report, null, 2)], {
                type: 'application/json',
              })
              const url = URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url
              a.download = `compliance-${report.report_id}.json`
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
            <h2 className="text-lg font-semibold text-text-0">Report Details</h2>
          </CardHeader>
          <CardBody>
            <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <dt className="text-sm text-text-3 mb-1">Report ID</dt>
                <dd className="text-sm font-mono text-text-0">{report.report_id}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Assessment ID</dt>
                <dd className="text-sm font-mono text-text-0">{report.assessment_id}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Generated</dt>
                <dd className="text-sm text-text-0">{formatDateTime(report.generated_at)}</dd>
              </div>
              {report.as_of && (
                <div>
                  <dt className="text-sm text-text-3 mb-1">As-of Date</dt>
                  <dd className="text-sm text-text-0">{report.as_of}</dd>
                </div>
              )}
            </dl>
          </CardBody>
        </Card>

        {report.summary && Object.keys(report.summary).length > 0 && (
          <Card>
            <CardHeader>
              <h2 className="text-lg font-semibold text-text-0">Summary</h2>
            </CardHeader>
            <CardBody>
              <pre className="text-sm text-text-1 bg-dark-primary p-4 rounded overflow-x-auto border border-dark-tertiary">
                {JSON.stringify(report.summary, null, 2)}
              </pre>
            </CardBody>
          </Card>
        )}

        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-text-0">Complete Report</h2>
          </CardHeader>
          <CardBody>
            <pre className="text-xs text-text-1 bg-dark-primary p-4 rounded overflow-x-auto max-h-[600px] border border-dark-tertiary">
              {JSON.stringify(report.report, null, 2)}
            </pre>
          </CardBody>
        </Card>

      </div>
    </div>
  )
}
