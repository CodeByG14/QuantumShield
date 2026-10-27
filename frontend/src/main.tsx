import React, { useEffect, useState } from 'react'
import ReactDOM from 'react-dom/client'
import { RouterProvider } from 'react-router-dom'
import { router } from '@/app/router'
import { api } from '@/lib/api-client'
import { Loading } from '@/components/ui/Loading'
import { ErrorMessage } from '@/components/ui/ErrorMessage'
import './styles/index.css'

function App() {
  const [sessionReady, setSessionReady] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // Initialize session on app mount
    initializeSession()
  }, [])

  async function initializeSession() {
    try {
      // Call GET /session to ensure session cookie is set
      await api.getSession()
      setSessionReady(true)
    } catch (err) {
      console.error('Session initialization failed:', err)
      setError('Failed to initialize session. Please check if the backend is running.')
    }
  }

  if (error) {
    return (
      <ErrorMessage
        title="Connection Error"
        message={error}
        onRetry={initializeSession}
        fullScreen
      />
    )
  }

  if (!sessionReady) {
    return <Loading fullScreen text="Initializing session..." />
  }

  return <RouterProvider router={router} />
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
