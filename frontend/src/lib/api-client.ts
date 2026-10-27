import type {
  SessionOut,
  SessionUpdate,
  ProjectOut,
  ProjectCreate,
  ScanFormData,
  ScanAccepted,
  ScanStatusOut,
  ScanListOut,
  FindingsOut,
  PlanRequest,
  PlanOut,
  ComplianceRequest,
  ComplianceOut,
  DiffRequest,
  DiffOut,
  HealthResponse,
} from '@/types/api'
import { APIError, NetworkError, parseErrorResponse } from '@/lib/api-errors'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

/**
 * Base fetch wrapper with error handling and session credentials
 */
async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`

  try {
    const response = await fetch(url, {
      ...options,
      credentials: 'include', // Required for session cookie
      headers: {
        ...options.headers,
      },
    })

    if (!response.ok) {
      throw await parseErrorResponse(response)
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return undefined as T
    }

    const contentType = response.headers.get('content-type')
    if (contentType?.includes('application/json')) {
      return await response.json()
    }

    // For non-JSON responses (like file downloads)
    return response as unknown as T
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }

    // Network error or other fetch failure
    if (error instanceof TypeError) {
      throw new NetworkError(
        'Network request failed. Please check your connection and ensure the backend is running.'
      )
    }

    throw error
  }
}

/**
 * GET request helper
 */
async function get<T>(endpoint: string): Promise<T> {
  return apiFetch<T>(endpoint, { method: 'GET' })
}

/**
 * POST request helper with JSON body
 */
async function post<T>(endpoint: string, data: unknown): Promise<T> {
  return apiFetch<T>(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
}

/**
 * POST request helper with multipart/form-data
 * Do NOT manually set Content-Type; browser will set it with boundary
 */
async function postMultipart<T>(endpoint: string, formData: FormData): Promise<T> {
  return apiFetch<T>(endpoint, {
    method: 'POST',
    body: formData,
  })
}

/**
 * PATCH request helper with JSON body
 */
async function patch<T>(endpoint: string, data: unknown): Promise<T> {
  return apiFetch<T>(endpoint, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
}

// ============================================================================
// API Endpoints
// ============================================================================

export const api = {
  // --- System ---
  health: () => get<HealthResponse>('/health'),

  // --- Session ---
  getSession: () => get<SessionOut>('/session'),
  updateSession: (data: SessionUpdate) => patch<SessionOut>('/session', data),

  // --- Projects ---
  listProjects: () => get<ProjectOut[]>('/projects'),
  createProject: (data: ProjectCreate) => post<ProjectOut>('/projects', data),
  getProject: (projectId: string) => get<ProjectOut>(`/projects/${projectId}`),
  listProjectScans: (projectId: string, limit = 50, offset = 0) =>
    get<ScanListOut>(`/projects/${projectId}/scans?limit=${limit}&offset=${offset}`),

  // --- Scans ---
  startScan: (data: ScanFormData) => {
    const formData = new FormData()
    formData.append('source_type', data.source_type)

    if (data.project_id) {
      formData.append('project_id', data.project_id)
    }
    if (data.project_name) {
      formData.append('project_name', data.project_name)
    }
    if (data.description) {
      formData.append('description', data.description)
    }
    if (data.repository_url) {
      formData.append('repository_url', data.repository_url)
    }
    if (data.context_json) {
      formData.append('context_json', data.context_json)
    }
    if (data.file) {
      formData.append('file', data.file)
    }

    return postMultipart<ScanAccepted>('/scan', formData)
  },

  getScanStatus: (scanRunId: string) =>
    get<ScanStatusOut>(`/scans/${scanRunId}`),

  getScanAssessment: (scanRunId: string) =>
    get<Record<string, any>>(`/scans/${scanRunId}/assessment`),

  // --- Assessments ---
  getAssessment: (assessmentId: string) =>
    get<Record<string, any>>(`/assessments/${assessmentId}`),

  getFindings: (
    assessmentId: string,
    params?: {
      algorithm?: string
      role?: string
      status?: string
      risk_level?: string
      limit?: number
      offset?: number
    }
  ) => {
    const query = new URLSearchParams()
    if (params?.algorithm) query.append('algorithm', params.algorithm)
    if (params?.role) query.append('role', params.role)
    if (params?.status) query.append('status', params.status)
    if (params?.risk_level) query.append('risk_level', params.risk_level)
    query.append('limit', String(params?.limit ?? 50))
    query.append('offset', String(params?.offset ?? 0))

    return get<FindingsOut>(`/assessments/${assessmentId}/findings?${query}`)
  },

  // --- Migration Plans ---
  createPlan: (data: PlanRequest) => post<PlanOut>('/plan', data),
  getPlan: (planId: string) => get<PlanOut>(`/plans/${planId}`),

  // --- Compliance Reports ---
  createCompliance: (data: ComplianceRequest) =>
    post<ComplianceOut>('/compliance', data),
  getCompliance: (reportId: string) =>
    get<ComplianceOut>(`/compliance/${reportId}`),

  // --- Comparisons/Diffs ---
  createDiff: (data: DiffRequest) => post<DiffOut>('/diff', data),
  getDiff: (diffId: string) => get<DiffOut>(`/diffs/${diffId}`),
}
