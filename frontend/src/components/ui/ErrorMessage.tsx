import { Button } from './Button'

interface ErrorMessageProps {
  title?: string
  message: string
  onRetry?: () => void
  fullScreen?: boolean
}

export function ErrorMessage({
  title = 'Error',
  message,
  onRetry,
  fullScreen = false,
}: ErrorMessageProps) {
  const content = (
    <div className="text-center max-w-md">
      <div className="mb-4">
        <svg
          className="mx-auto h-12 w-12 text-brand-primary"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
        </svg>
      </div>
      <h3 className="text-lg font-semibold text-text-0 mb-2">{title}</h3>
      <p className="text-text-2 mb-4">{message}</p>
      {onRetry && (
        <Button onClick={onRetry} variant="primary">
          Try Again
        </Button>
      )}
    </div>
  )

  if (fullScreen) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background-0 p-4">
        {content}
      </div>
    )
  }

  return (
    <div className="flex items-center justify-center p-8 bg-background-1 rounded-md border border-neutral-100">
      {content}
    </div>
  )
}

interface InlineErrorProps {
  message: string
  id?: string
}

export function InlineError({ message, id }: InlineErrorProps) {
  return (
    <div
      id={id}
      className="text-sm text-brand-primary mt-1 flex items-start gap-1"
      role="alert"
    >
      <svg
        className="h-4 w-4 flex-shrink-0 mt-0.5"
        fill="currentColor"
        viewBox="0 0 20 20"
      >
        <path
          fillRule="evenodd"
          d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
          clipRule="evenodd"
        />
      </svg>
      <span>{message}</span>
    </div>
  )
}
