import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '@/lib/api-client'
import { getErrorMessage, isValidationError } from '@/lib/api-errors'
import type { ScanFormData, ScanInputKind } from '@/types/api'
import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { FileUpload } from '@/components/ui/FileUpload'
import { InlineError } from '@/components/ui/ErrorMessage'

type SourceType = ScanInputKind

interface ScanFormState {
  sourceType: SourceType
  projectName: string
  description: string
  // GitHub
  repositoryUrl: string
  // ZIP / SBOM / CBOM
  file: File | null
}

export function NewScanPage() {
  const navigate = useNavigate()
  const [formState, setFormState] = useState<ScanFormState>({
    sourceType: 'github_repository',
    projectName: '',
    description: '',
    repositoryUrl: '',
    file: null,
  })
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [submitting, setSubmitting] = useState(false)
  const [generalError, setGeneralError] = useState<string | null>(null)

  function updateField<K extends keyof ScanFormState>(
    field: K,
    value: ScanFormState[K]
  ) {
    setFormState((prev) => ({ ...prev, [field]: value }))
    // Clear error for this field when user makes changes
    if (errors[field]) {
      setErrors((prev) => {
        const newErrors = { ...prev }
        delete newErrors[field]
        return newErrors
      })
    }
  }

  function validateForm(): boolean {
    const newErrors: Record<string, string> = {}

    // Project name is optional but if provided must be valid
    if (formState.projectName.trim() && formState.projectName.length > 255) {
      newErrors.projectName = 'Project name must not exceed 255 characters'
    }

    // Source-specific validation
    if (formState.sourceType === 'github_repository') {
      const url = formState.repositoryUrl.trim()
      if (!url) {
        newErrors.repositoryUrl = 'GitHub repository URL is required'
      } else {
        // Basic GitHub URL validation
        try {
          const parsed = new URL(url)
          if (parsed.hostname !== 'github.com') {
            newErrors.repositoryUrl = 'Only github.com URLs are supported'
          }
          if (parsed.search || parsed.hash) {
            newErrors.repositoryUrl = 'URL must not contain query strings or fragments'
          }
          // Check for credentials in URL
          if (parsed.username || parsed.password) {
            newErrors.repositoryUrl = 'URL must not contain credentials'
          }
        } catch {
          newErrors.repositoryUrl = 'Invalid URL format'
        }
      }
    } else {
      // ZIP, SBOM, or CBOM - file required
      if (!formState.file) {
        newErrors.file = 'Please select a file to upload'
      } else {
        const fileName = formState.file.name.toLowerCase()
        
        if (formState.sourceType === 'zip_archive') {
          if (!fileName.endsWith('.zip')) {
            newErrors.file = 'ZIP archive must have a .zip extension'
          }
        } else if (formState.sourceType === 'sbom' || formState.sourceType === 'cbom') {
          if (!fileName.endsWith('.json')) {
            newErrors.file = 'SBOM/CBOM file must have a .json extension'
          }
        }
      }
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setGeneralError(null)

    if (!validateForm()) {
      return
    }

    try {
      setSubmitting(true)

      const scanData: ScanFormData = {
        source_type: formState.sourceType,
        project_name: formState.projectName.trim() || undefined,
        description: formState.description.trim() || undefined,
      }

      if (formState.sourceType === 'github_repository') {
        scanData.repository_url = formState.repositoryUrl.trim()
      } else {
        scanData.file = formState.file!
      }

      const result = await api.startScan(scanData)
      
      // Navigate to scan status page
      navigate(`/scans/${result.scan_run_id}`)
    } catch (err) {
      if (isValidationError(err)) {
        setGeneralError(getErrorMessage(err))
      } else {
        setGeneralError(getErrorMessage(err))
      }
    } finally {
      setSubmitting(false)
    }
  }

  const sourceTypes: Array<{ value: SourceType; label: string; description: string }> = [
    {
      value: 'github_repository',
      label: 'GitHub Repository',
      description: 'Clone and scan a public GitHub repository',
    },
    {
      value: 'zip_archive',
      label: 'ZIP Archive',
      description: 'Upload a compressed source code archive',
    },
    {
      value: 'sbom',
      label: 'SBOM (Software Bill of Materials)',
      description: 'Import CycloneDX or SPDX 2.x JSON',
    },
    {
      value: 'cbom',
      label: 'CBOM (Cryptography Bill of Materials)',
      description: 'Import CycloneDX CBOM JSON',
    },
  ]

  return (
    <div>
      <PageHeader
        title="New Scan"
        description="Start a cryptographic analysis by selecting your source type"
      />

      <form onSubmit={handleSubmit}>
        <div className="space-y-6 max-w-4xl">
          {/* Project Information */}
          <Card>
            <CardBody>
              <h3 className="text-lg font-semibold text-text-0 mb-4">
                Project Information
              </h3>
              <div className="space-y-4">
                <Input
                  label="Project Name"
                  value={formState.projectName}
                  onChange={(e) => updateField('projectName', e.target.value)}
                  error={errors.projectName}
                  placeholder="Leave empty to create from source name"
                  maxLength={255}
                />
                <Textarea
                  label="Description"
                  value={formState.description}
                  onChange={(e) => updateField('description', e.target.value)}
                  placeholder="Optional project description..."
                  maxLength={5000}
                />
              </div>
            </CardBody>
          </Card>

          {/* Source Type Selection */}
          <Card>
            <CardBody>
              <h3 className="text-lg font-semibold text-text-0 mb-4">
                Select Source Type
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                {sourceTypes.map((type) => (
                  <button
                    key={type.value}
                    type="button"
                    aria-pressed={formState.sourceType === type.value}
                    onClick={() => {
                      updateField('sourceType', type.value)
                      // Clear source-specific fields
                      updateField('repositoryUrl', '')
                      updateField('file', null)
                      setErrors({})
                    }}
                    className={`
                      text-left p-4 rounded-lg border-2 transition-all duration-150
                      focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent
                      ${
                        formState.sourceType === type.value
                          ? 'border-brand-accent bg-dark-tertiary text-text-0'
                          : 'border-dark-tertiary bg-dark-secondary text-text-0 hover:border-text-3'
                      }
                    `}
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className={`
                          mt-1 w-5 h-5 rounded-full border-2 flex items-center justify-center
                          ${
                            formState.sourceType === type.value
                              ? 'border-brand-accent'
                              : 'border-text-3'
                          }
                        `}
                      >
                        {formState.sourceType === type.value && (
                          <div className="w-3 h-3 rounded-full bg-brand-accent" />
                        )}
                      </div>
                      <div className="flex-1">
                        <p className="font-medium text-text-0">{type.label}</p>
                        <p className="text-sm text-text-3 mt-1">{type.description}</p>
                      </div>
                    </div>
                  </button>
                ))}
              </div>

              {/* Source-Specific Input */}
              <div className="mt-6 p-6 bg-dark-primary rounded-lg border border-dark-tertiary">
                {formState.sourceType === 'github_repository' && (
                  <div>
                    <Input
                      label="GitHub Repository URL"
                      value={formState.repositoryUrl}
                      onChange={(e) => updateField('repositoryUrl', e.target.value)}
                      error={errors.repositoryUrl}
                      placeholder="https://github.com/owner/repository"
                      helperText="Enter a public GitHub repository URL"
                      required
                    />
                  </div>
                )}

                {formState.sourceType === 'zip_archive' && (
                  <FileUpload
                    label="ZIP Archive"
                    accept=".zip"
                    maxSizeMB={50}
                    selectedFile={formState.file}
                    onFileSelect={(file) => updateField('file', file)}
                    error={errors.file}
                    helperText="Maximum 50 MB. Only .zip files are accepted."
                  />
                )}

                {formState.sourceType === 'sbom' && (
                  <FileUpload
                    label="SBOM File"
                    accept=".json"
                    maxSizeMB={50}
                    selectedFile={formState.file}
                    onFileSelect={(file) => updateField('file', file)}
                    error={errors.file}
                    helperText="CycloneDX or SPDX 2.x JSON format. Maximum 50 MB."
                  />
                )}

                {formState.sourceType === 'cbom' && (
                  <FileUpload
                    label="CBOM File"
                    accept=".json"
                    maxSizeMB={50}
                    selectedFile={formState.file}
                    onFileSelect={(file) => updateField('file', file)}
                    error={errors.file}
                    helperText="CycloneDX CBOM JSON format. Maximum 50 MB."
                  />
                )}
              </div>
            </CardBody>
          </Card>

          {/* General Error */}
          {generalError && (
            <div className="p-4 bg-red-900 bg-opacity-20 border border-brand-primary rounded-md">
              <InlineError message={generalError} />
            </div>
          )}

          {/* Submit */}
          <div className="flex gap-3 justify-end">
            <Button
              type="button"
              variant="outline"
              onClick={() => navigate(-1)}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" isLoading={submitting}>
              {submitting ? 'Starting Scan...' : 'Start Scan'}
            </Button>
          </div>
        </div>
      </form>
    </div>
  )
}
