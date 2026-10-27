import { useEffect, useState, useRef } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { api } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/api-errors'
import { formatDateTime, formatDuration } from '@/lib/formatters'
import type { ScanStatusOut } from '@/types/api'
import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Loading, LoadingSpinner } from '@/components/ui/Loading'
import { ErrorMessage } from '@/components/ui/ErrorMessage'
import { StatusBadge } from '@/components/ui/Badge'

const POLL_INTERVAL_MS = 3000 // 3 seconds
const MAX_POLL_ATTEMPTS = 200 // 10 minutes maximum

export function ScanStatusPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const [scan, setScan] = useState<ScanStatusOut | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [polling, setPolling] = useState(false)
  const pollCountRef = useRef(0)
  const pollTimeoutRef = useRef<number | null>(null)

  useEffect(() => {
    if (!scanId) {
      setError('No scan ID provided')
      setLoading(false)
      return
    }

    loadScanStatus()

    // Cleanup polling on unmount
    return () => {
      if (pollTimeoutRef.current) {
        clearTimeout(pollTimeoutRef.current)
      }
    }
  }, [scanId])

  async function loadScanStatus() {
    if (!scanId) return

    try {
      setError(null)
      const data = await api.getScanStatus(scanId)
      setScan(data)
      setLoading(false)

      // Start polling if scan is queued or running
      if (data.status === 'queued' || data.status === 'running') {
        scheduleNextPoll()
      }
    } catch (err) {
      setError(getErrorMessage(err))
      setLoading(false)
      setPolling(false)
    }
  }

  function scheduleNextPoll() {
    if (pollCountRef.current >= MAX_POLL_ATTEMPTS) {
      setPolling(false)
      return
    }

    setPolling(true)
    pollCountRef.current += 1

    pollTimeoutRef.current = window.setTimeout(() => {
      loadScanStatus()
    }, POLL_INTERVAL_MS)
  }

  function handleRefresh() {
    pollCountRef.current = 0
    loadScanStatus()
  }

  if (loading) {
    return <Loading fullScreen text="Loading scan status..." />
  }

  if (error || !scan) {
    return (
      <ErrorMessage
        title="Failed to Load Scan"
        message={error || 'Scan not found'}
        onRetry={handleRefresh}
        fullScreen
      />
    )
  }

  const isTerminal = ['completed', 'failed', 'cancelled'].includes(scan.status)
  const showAssessmentLink = scan.status === 'completed' && scan.assessment_id

  return (
    <div>
      <PageHeader
        title="Scan Status"
        description={`Tracking scan: ${scan.input_name || scan.scan_run_id}`}
        action={
          <div className="flex gap-3">
            <Button
              variant="outline"
              onClick={handleRefresh}
              disabled={polling}
            >
              {polling ? (
                <>
                  <LoadingSpinner className="h-4 w-4 mr-2" />
                  Refreshing...
                </>
              ) : (
                <>
                  <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  Refresh
                </>
              )}
            </Button>
            {showAssessmentLink && (
              <Button
                variant="primary"
                onClick={() => navigate(`/scans/${scan.scan_run_id}/results`)}
              >
                View Results →
              </Button>
            )}
          </div>
        }
      />

      <div className="space-y-6 max-w-4xl">
        {/* Status Card */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-text-0">Scan Status</h2>
              <StatusBadge status={scan.status} />
            </div>
          </CardHeader>
          <CardBody>
            <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <dt className="text-sm text-text-3 mb-1">Scan ID</dt>
                <dd className="text-sm font-mono text-text-0">{scan.scan_run_id}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Project ID</dt>
                <dd className="text-sm font-mono text-text-0">
                  <Link
                    to={`/projects/${scan.project_id}`}
                    className="text-brand-accent hover:underline"
                  >
                    {scan.project_id}
                  </Link>
                </dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Source Type</dt>
                <dd className="text-sm text-text-0">{scan.input_kind}</dd>
              </div>
              <div>
                <dt className="text-sm text-text-3 mb-1">Source Name</dt>
                <dd className="text-sm text-text-0">{scan.input_name || 'N/A'}</dd>
              </div>
              {scan.source_revision && (
                <div>
                  <dt className="text-sm text-text-3 mb-1">Revision</dt>
                  <dd className="text-sm font-mono text-text-0">{scan.source_revision}</dd>
                </div>
              )}
              <div>
                <dt className="text-sm text-text-3 mb-1">Started At</dt>
                <dd className="text-sm text-text-0">{formatDateTime(scan.started_at)}</dd>
              </div>
              {scan.completed_at && (
                <>
                  <div>
                    <dt className="text-sm text-text-3 mb-1">Completed At</dt>
                    <dd className="text-sm text-text-0">{formatDateTime(scan.completed_at)}</dd>
                  </div>
                  <div>
                    <dt className="text-sm text-text-3 mb-1">Duration</dt>
                    <dd className="text-sm text-text-0">
                      {formatDuration(scan.started_at, scan.completed_at)}
                    </dd>
                  </div>
                </>
              )}
            </dl>
          </CardBody>
        </Card>

        {/* Progress Indicator */}
        {!isTerminal && (
          <Card>
            <CardBody>
              <div className="flex items-center gap-4">
                <LoadingSpinner className="h-8 w-8 text-brand-accent" />
                <div className="flex-1">
                  <p className="text-text-0 font-medium">
                    {scan.status === 'queued' ? 'Scan is queued...' : 'Scan is running...'}
                  </p>
                  <p className="text-sm text-text-3 mt-1">
                    {polling
                      ? `Checking status... (${pollCountRef.current}/${MAX_POLL_ATTEMPTS})`
                      : 'Stopped polling'}
                  </p>
                </div>
              </div>
            </CardBody>
          </Card>
        )}

        {/* Error Message */}
        {scan.status === 'failed' && scan.error_message && (
          <Card>
            <CardBody>
              <div className="flex items-start gap-3">
                <svg
                  className="h-6 w-6 text-brand-primary flex-shrink-0 mt-0.5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                  />
                </svg>
                <div>
                  <h3 className="font-semibold text-text-0 mb-1">Scan Failed</h3>
                  <p className="text-sm text-text-2">{scan.error_message}</p>
                </div>
              </div>
            </CardBody>
          </Card>
        )}

        {/* Assessment Summary */}
        {scan.assessment_summary && (
          <Card>
            <CardHeader>
              <h2 className="text-lg font-semibold text-text-0">Assessment Summary</h2>
            </CardHeader>
            <CardBody>
              <pre className="text-sm text-text-1 bg-neutral-500 p-4 rounded overflow-x-auto">
                {JSON.stringify(scan.assessment_summary, null, 2)}
              </pre>
            </CardBody>
          </Card>
        )}

        {/* Actions */}
        {showAssessmentLink && (
          <Card>
            <CardBody>
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-text-0 mb-1">Scan Completed</h3>
                  <p className="text-sm text-text-3">
                    Assessment ID: <span className="font-mono">{scan.assessment_id}</span>
                  </p>
                </div>
                <div className="flex gap-3">
                  <Button
                    variant="outline"
                    onClick={() => navigate(`/assessments/${scan.assessment_id}/findings`)}
                  >
                    View Findings
                  </Button>
                  <Button
                    variant="primary"
                    onClick={() => navigate(`/scans/${scan.scan_run_id}/results`)}
                  >
                    View Full Results
                  </Button>
                </div>
              </div>
            </CardBody>
          </Card>
        )}

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
