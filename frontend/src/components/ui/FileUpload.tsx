import { useRef, useState } from 'react'

interface FileUploadProps {
  accept?: string
  maxSizeMB?: number
  onFileSelect: (file: File | null) => void
  selectedFile: File | null
  error?: string
  label: string
  helperText?: string
}

export function FileUpload({
  accept,
  maxSizeMB = 50,
  onFileSelect,
  selectedFile,
  error,
  label,
  helperText,
}: FileUploadProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragActive, setDragActive] = useState(false)

  function handleFile(file: File | undefined) {
    if (!file) {
      onFileSelect(null)
      return
    }

    // Size check
    const maxBytes = maxSizeMB * 1024 * 1024
    if (file.size > maxBytes) {
      onFileSelect(null)
      return
    }

    onFileSelect(file)
  }

  function handleDrag(e: React.DragEvent) {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0])
    }
  }

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0])
    }
  }

  function handleRemove() {
    onFileSelect(null)
    if (inputRef.current) {
      inputRef.current.value = ''
    }
  }

  return (
    <div>
      <label className="block text-sm font-medium text-text-0 mb-2">
        {label}
      </label>

      <div
        className={`
          relative border-2 border-dashed rounded-lg p-6 text-center
          transition-colors duration-150
          ${dragActive ? 'border-brand-accent bg-blue-900 bg-opacity-20' : 'border-dark-tertiary'}
          ${error ? 'border-brand-primary bg-red-900 bg-opacity-20' : ''}
          ${!selectedFile ? 'hover:border-text-3 cursor-pointer' : ''}
        `}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => !selectedFile && inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          onChange={handleChange}
          className="hidden"
          aria-describedby={error ? 'file-error' : undefined}
          aria-invalid={error ? 'true' : 'false'}
        />

        {!selectedFile ? (
          <>
            <svg
              className="mx-auto h-12 w-12 text-text-3 mb-3"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1}
                d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
              />
            </svg>
            <p className="text-sm text-text-1 mb-1">
              <span className="font-medium text-brand-accent">Click to upload</span> or
              drag and drop
            </p>
            {helperText && <p className="text-xs text-text-3">{helperText}</p>}
          </>
        ) : (
          <div className="flex items-center justify-center gap-3">
            <svg
              className="h-8 w-8 text-green-400"
              fill="currentColor"
              viewBox="0 0 20 20"
            >
              <path
                fillRule="evenodd"
                d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z"
                clipRule="evenodd"
              />
            </svg>
            <div className="flex-1 text-left">
              <p className="text-sm font-medium text-text-0 truncate">
                {selectedFile.name}
              </p>
              <p className="text-xs text-text-3">
                {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
              </p>
            </div>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                handleRemove()
              }}
              className="text-brand-primary hover:text-red-700 transition-colors"
              aria-label="Remove file"
            >
              <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
                <path
                  fillRule="evenodd"
                  d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                  clipRule="evenodd"
                />
              </svg>
            </button>
          </div>
        )}
      </div>

      {error && (
        <p id="file-error" className="text-sm text-brand-primary mt-2" role="alert">
          {error}
        </p>
      )}
    </div>
  )
}
