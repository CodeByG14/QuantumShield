import React from 'react'

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string
  error?: string
  helperText?: string
}

export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ label, error, helperText, id, className = '', ...props }, ref) => {
    const textareaId = id || `textarea-${Math.random().toString(36).substring(7)}`
    const errorId = error ? `${textareaId}-error` : undefined
    const helperId = helperText ? `${textareaId}-helper` : undefined

    return (
      <div className="w-full">
        {label && (
          <label
            htmlFor={textareaId}
            className="block text-sm font-medium text-text-0 mb-1"
          >
            {label}
          </label>
        )}
        <textarea
          ref={ref}
          id={textareaId}
          aria-invalid={error ? 'true' : 'false'}
          aria-describedby={error ? errorId : helperId}
          className={`
            w-full px-3 py-2 text-text-0 bg-dark-primary border rounded-md
            transition-colors duration-150
            focus:outline-none focus:ring-2 focus:ring-brand-accent focus:border-transparent
            disabled:opacity-50 disabled:cursor-not-allowed
            resize-vertical min-h-[100px]
            placeholder:text-text-3
            ${error ? 'border-brand-primary' : 'border-dark-tertiary'}
            ${className}
          `}
          {...props}
        />
        {error && (
          <p id={errorId} className="text-sm text-brand-primary mt-1" role="alert">
            {error}
          </p>
        )}
        {helperText && !error && (
          <p id={helperId} className="text-sm text-text-3 mt-1">
            {helperText}
          </p>
        )}
      </div>
    )
  }
)

Textarea.displayName = 'Textarea'
