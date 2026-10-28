import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/api-errors'
import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'

export function ReportsPage() {
  const { assessmentId } = useParams<{ assessmentId: string }>()
  const navigate = useNavigate()
  const [generating, setGenerating] = useState<'plan' | 'compliance' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [complianceDate, setComplianceDate] = useState('')

  async function generateMigrationPlan() {
    if (!assessmentId) return

    try {
      setGenerating('plan')
      setError(null)
      const plan = await api.createPlan({ assessment_id: assessmentId })
      navigate(`/plans/${plan.migration_plan_id}`)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setGenerating(null)
    }
  }

  async function generateComplianceReport() {
    if (!assessmentId || !complianceDate) return

    try {
      setGenerating('compliance')
      setError(null)
      const report = await api.createCompliance({
        assessment_id: assessmentId,
        as_of: complianceDate,
      })
      navigate(`/compliance/${report.report_id}`)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setGenerating(null)
    }
  }

  return (
    <div>
      <PageHeader
        title="Generate Reports"
        description={`Create reports for assessment ${assessmentId}`}
        backAction={
          <Button variant="ghost" onClick={() => navigate(-1)}>
            ← Back
          </Button>
        }
      />

      <div className="space-y-6 max-w-4xl">
        {error && (
          <div className="p-4 bg-red-900 bg-opacity-20 border border-brand-primary rounded-md text-sm text-brand-primary" role="alert">
            {error}
          </div>
        )}

        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-text-0">Migration Plan</h2>
          </CardHeader>
          <CardBody>
            <p className="text-sm text-text-2 mb-4">
              Generate detailed migration plan with PQ algorithm recommendations.
            </p>
            <Button
              variant="primary"
              onClick={generateMigrationPlan}
              isLoading={generating === 'plan'}
              disabled={generating !== null}
            >
              Generate Migration Plan
            </Button>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-text-0">Compliance Report</h2>
          </CardHeader>
          <CardBody>
            <p className="text-sm text-text-2 mb-4">
              Generate compliance report for post-quantum standards.
            </p>
            <div className="space-y-4">
              <label
                htmlFor="compliance-as-of-date"
                className="block text-sm font-medium text-text-0 mb-1"
              >
                As-of Date <span className="text-brand-primary">*</span>
              </label>
              <Input
                id="compliance-as-of-date"
                type="date"
                className="[color-scheme:dark]"
                required
                value={complianceDate}
                onChange={(e) => setComplianceDate(e.target.value)}
                helperText="Required to generate the compliance report."
              />
              <Button
                variant="primary"
                onClick={generateComplianceReport}
                isLoading={generating === 'compliance'}
                disabled={generating !== null || !complianceDate}
              >
                Generate Compliance Report
              </Button>
            </div>
          </CardBody>
        </Card>

      </div>
    </div>
  )
}
