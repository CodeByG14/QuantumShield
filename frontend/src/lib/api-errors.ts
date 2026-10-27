import type { ErrorOut } from '@/types/api'

export class APIError extends Error {
  public readonly status: number
  public readonly detail: string

  constructor(status: number, detail: string) {
    super(detail)
    this.name = 'APIError'
    this.status = status
    this.detail = detail
  }
}

export class NetworkError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NetworkError'
  }
}

/**
 * Parse an HTTP error response into an APIError
 */
export async function parseErrorResponse(response: Response): Promise<APIError> {
  let detail = `HTTP ${response.status}: ${response.statusText}`
  
  try {
    const contentType = response.headers.get('content-type')
    if (contentType?.includes('application/json')) {
      const error: ErrorOut = await response.json()
      detail = error.detail || detail
    }
  } catch {
    // If JSON parsing fails, use the default detail
  }

  return new APIError(response.status, detail)
}

/**
 * Normalize an error into a user-friendly message
 */
export function getErrorMessage(error: unknown): string {
  if (error instanceof APIError) {
    return error.detail
  }
  
  if (error instanceof NetworkError) {
    return error.message
  }

  if (error instanceof Error) {
    return error.message
  }

  return 'An unexpected error occurred'
}

/**
 * Check if error is a not-found error
 */
export function isNotFoundError(error: unknown): boolean {
  return error instanceof APIError && error.status === 404
}

/**
 * Check if error is a validation error
 */
export function isValidationError(error: unknown): boolean {
  return error instanceof APIError && error.status === 422
}

/**
 * Check if error is an authentication/session error
 */
export function isAuthError(error: unknown): boolean {
  return error instanceof APIError && (error.status === 401 || error.status === 403)
}
