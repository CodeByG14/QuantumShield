import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { api } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/api-errors'
import type { FindingsOut } from '@/types/api'
import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Loading } from '@/components/ui/Loading'
import { ErrorMessage } from '@/components/ui/ErrorMessage'
import { EmptyState } from '@/components/ui/EmptyState'
import { Badge } from '@/components/ui/Badge'
import { Input } from '@/components/ui/Input'

interface FindingsFilters {
  algorithm?: string
  role?: string
  status?: string
  risk_level?: string
}

export function FindingsPage() {
  const { assessmentId } = useParams<{ assessmentId: string }>()
  const navigate = useNavigate()
  const [findings, setFindings] = useState<FindingsOut | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [currentPage, setCurrentPage] = useState(1)
  const [filters, setFilters] = useState<FindingsFilters>({})
  const [showFilters, setShowFilters] = useState(false)

  const itemsPerPage = 20

  useEffect(() => {
    if (!assessmentId) {
      setError('No assessment ID provided')
      setLoading(false)
      return
    }

    loadFindings()
  }, [assessmentId, currentPage, filters])

  async function loadFindings() {
    if (!assessmentId) return

    try {
      setLoading(true)
      setError(null)
      const offset = (currentPage - 1) * itemsPerPage
      const data = await api.getFindings(assessmentId, {
        ...filters,
        limit: itemsPerPage,
        offset,
      })
      setFindings(data)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  function handleFilterChange(key: keyof FindingsFilters, value: string) {
    setFilters((prev) => ({
      ...prev,
      [key]: value || undefined,
    }))
    setCurrentPage(1) // Reset to first page
  }

  function clearFilters() {
    setFilters({})
    setCurrentPage(1)
  }

  if (loading && !findings) {
    return <Loading fullScreen text="Loading findings..." />
  }

  if (error && !findings) {
    return (
      <ErrorMessage
        title="Failed to Load Findings"
        message={error}
        onRetry={loadFindings}
        fullScreen
      />
    )
  }

  if (!findings) {
    return null
  }

  const totalPages = Math.ceil(findings.count / itemsPerPage)
  const hasFilters = Object.values(filters).some((v) => v !== undefined)

  return (
    <div>
      <PageHeader
        title="Findings"
        description={`${findings.count} finding${findings.count !== 1 ? 's' : ''} in assessment ${assessmentId}`}
        backAction={
          <Button variant="ghost" onClick={() => navigate(-1)}>
            ← Back
          </Button>
        }
        action={
          <Link to={`/assessments/${assessmentId}/reports`}>
            <Button variant="primary">Generate Reports</Button>
          </Link>
        }
      />

      <div className="space-y-6">
        {/* Filters */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-text-0">Filters</h2>
              <div className="flex gap-2">
                {hasFilters && (
                  <Button variant="ghost" size="sm" onClick={clearFilters}>
                    Clear All
                  </Button>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowFilters(!showFilters)}
                >
                  {showFilters ? 'Hide' : 'Show'} Filters
                </Button>
              </div>
            </div>
          </CardHeader>
          {showFilters && (
            <CardBody>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Input
                  label="Algorithm"
                  value={filters.algorithm || ''}
                  onChange={(e) => handleFilterChange('algorithm', e.target.value)}
                  placeholder="e.g., RSA, AES"
                />
                <Input
                  label="Role"
                  value={filters.role || ''}
                  onChange={(e) => handleFilterChange('role', e.target.value)}
                  placeholder="e.g., encryption, signing"
                />
                <Input
                  label="Status"
                  value={filters.status || ''}
                  onChange={(e) => handleFilterChange('status', e.target.value)}
                  placeholder="e.g., confirmed, potential"
                />
                <Input
                  label="Risk Level"
                  value={filters.risk_level || ''}
                  onChange={(e) => handleFilterChange('risk_level', e.target.value)}
                  placeholder="e.g., high, medium, low"
                />
              </div>
            </CardBody>
          )}
        </Card>

        {/* Findings List */}
        {findings.items.length === 0 ? (
          <Card>
            <CardBody>
              <EmptyState
                title="No Findings"
                description={
                  hasFilters
                    ? 'No findings match your current filters. Try adjusting or clearing them.'
                    : 'No cryptographic findings were detected in this assessment. This does not guarantee the absence of cryptography or security vulnerabilities.'
                }
                action={
                  hasFilters
                    ? {
                        label: 'Clear Filters',
                        onClick: clearFilters,
                      }
                    : undefined
                }
              />
            </CardBody>
          </Card>
        ) : (
          <div className="space-y-4">
            {findings.items.map((finding, index) => (
              <Card key={`finding-${index}`}>
                <CardBody>
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        {finding.algorithm && (
                          <Badge variant="info">
                            {finding.algorithm}
                          </Badge>
                        )}
                        {finding.role && (
                          <Badge variant="default">{finding.role}</Badge>
                        )}
                        {finding.status && (
                          <Badge
                            variant={
                              finding.status === 'confirmed'
                                ? 'success'
                                : 'warning'
                            }
                          >
                            {finding.status}
                          </Badge>
                        )}
                      </div>
                      {finding.description && (
                        <p className="text-sm text-text-1 mb-2">
                          {finding.description}
                        </p>
                      )}
                    </div>
                    {finding.risk && finding.risk.level && (
                      <Badge
                        variant={
                          finding.risk.level === 'high'
                            ? 'error'
                            : finding.risk.level === 'medium'
                            ? 'warning'
                            : 'default'
                        }
                      >
                        Risk: {finding.risk.level}
                      </Badge>
                    )}
                  </div>

                  {finding.location && (
                    <div className="text-xs font-mono text-text-1 bg-dark-primary p-2 rounded mb-2 border border-dark-tertiary">
                      {finding.location}
                    </div>
                  )}

                  {finding.evidence && finding.evidence.length > 0 && (
                    <details className="mt-3">
                      <summary className="text-sm font-medium text-text-2 cursor-pointer hover:text-text-0">
                        Evidence ({finding.evidence.length})
                      </summary>
                      <div className="mt-2 pl-4 border-l-2 border-dark-tertiary space-y-1">
                        {finding.evidence.map((ev: any, i: number) => (
                          <div key={i} className="text-xs text-text-3">
                            {typeof ev === 'string' ? ev : JSON.stringify(ev)}
                          </div>
                        ))}
                      </div>
                    </details>
                  )}

                  {finding.risk && (
                    <details className="mt-3">
                      <summary className="text-sm font-medium text-text-2 cursor-pointer hover:text-text-0">
                        Risk Details
                      </summary>
                      <pre className="mt-2 text-xs text-text-1 bg-dark-primary p-2 rounded overflow-x-auto border border-dark-tertiary">
                        {JSON.stringify(finding.risk, null, 2)}
                      </pre>
                    </details>
                  )}
                </CardBody>
              </Card>
            ))}
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <Card>
            <CardBody>
              <div className="flex items-center justify-between">
                <div className="text-sm text-text-2">
                  Showing {findings.offset + 1}–
                  {Math.min(findings.offset + findings.limit, findings.count)} of{' '}
                  {findings.count}
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    disabled={currentPage === 1 || loading}
                  >
                    ← Previous
                  </Button>
                  <span className="flex items-center px-3 text-sm text-text-1">
                    Page {currentPage} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages || loading}
                  >
                    Next →
                  </Button>
                </div>
              </div>
            </CardBody>
          </Card>
        )}

      </div>
    </div>
  )
}
