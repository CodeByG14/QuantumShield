// TypeScript types derived from backend Pydantic schemas
// Generated from src/quantumshield/api/schemas.py

export interface SessionOut {
  session_id: string
  display_name: string | null
  created_at: string
  last_seen_at: string
  expires_at: string | null
}

export interface SessionUpdate {
  display_name?: string | null
}

export interface ProjectCreate {
  project_name: string
  description?: string | null
}

export interface ProjectOut {
  project_id: string
  project_name: string
  description: string | null
  created_at: string
  updated_at: string
  archived: boolean
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'

export type ScanInputKind = 'github_repository' | 'zip_archive' | 'sbom' | 'cbom'

export interface ScanAccepted {
  scan_run_id: string
  project_id: string
  workspace_id: string
  status: ScanStatus
  input_kind: ScanInputKind
  input_name: string
  status_url: string
}

export interface ScanStatusOut {
  scan_run_id: string
  project_id: string
  input_kind: string
  input_name: string | null
  source_revision: string | null
  status: ScanStatus
  started_at: string
  completed_at: string | null
  error_message: string | null
  assessment_id: string | null
  assessment_summary: Record<string, any> | null
}

export interface ScanListOut {
  items: ScanStatusOut[]
  count: number
}

export interface DashboardSummary {
  project_count: number
  scan_count: number
  scans_by_status: Record<string, number>
  active_scan_count: number
  latest_assessment_count: number
  latest_assessment_risk_levels: Record<string, number>
  high_priority_risk_count: number
}

export interface AssessmentSummaryOut {
  assessment_id: string
  scan_run_id: string
  assessment_schema_version: string
  policy_version: string
  summary: Record<string, any>
  created_at: string
}

export interface FindingsOut {
  assessment_id: string
  items: Array<Record<string, any>>
  count: number
  limit: number
  offset: number
}

export interface PlanRequest {
  assessment_id: string
}

export interface PlanOut {
  migration_plan_id: string
  assessment_id: string
  plan: Record<string, any>
  summary: Record<string, any>
  generated_at: string
}

export interface ComplianceRequest {
  assessment_id: string
  migration_plan_id?: string | null
  as_of?: string | null // date as YYYY-MM-DD
}

export interface ComplianceOut {
  report_id: string
  assessment_id: string
  migration_plan_id: string | null
  as_of: string | null
  report: Record<string, any>
  summary: Record<string, any>
  generated_at: string
}

export interface DiffRequest {
  baseline_assessment_id: string
  current_assessment_id: string
}

export interface DiffOut {
  diff_id: string
  baseline_assessment_id: string
  current_assessment_id: string
  diff: Record<string, any>
  summary: Record<string, any>
  generated_at: string
}

export interface ErrorOut {
  detail: string
}

// Health check response
export interface HealthResponse {
  status: string
  database: string
}

// Scan submission form data
export interface ScanFormData {
  source_type: ScanInputKind
  project_id?: string
  project_name?: string
  description?: string
  repository_url?: string
  context_json?: string
  file?: File
}
