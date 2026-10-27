import { createBrowserRouter } from 'react-router-dom'
import { Layout } from '@/components/layout/Layout'
import { DashboardPage } from '@/features/dashboard/DashboardPage'
import { ProjectsListPage } from '@/features/projects/ProjectsListPage'
import { ProjectDetailPage } from '@/features/projects/ProjectDetailPage'
import { NewScanPage } from '@/features/scans/NewScanPage'
import { ScanStatusPage } from '@/features/scans/ScanStatusPage'
import { AssessmentResultsPage } from '@/features/assessments/AssessmentResultsPage'
import { FindingsPage } from '@/features/findings/FindingsPage'
import { ReportsPage } from '@/features/reports/ReportsPage'
import { MigrationPlanPage } from '@/features/reports/MigrationPlanPage'
import { CompliancePage } from '@/features/reports/CompliancePage'
import { NotFoundPage } from '@/features/common/NotFoundPage'

export const router = createBrowserRouter([
  {
    path: '/',
    element: <Layout />,
    children: [
      {
        index: true,
        element: <DashboardPage />,
      },
      {
        path: 'projects',
        element: <ProjectsListPage />,
      },
      {
        path: 'projects/:projectId',
        element: <ProjectDetailPage />,
      },
      {
        path: 'scans/new',
        element: <NewScanPage />,
      },
      {
        path: 'scans/:scanId',
        element: <ScanStatusPage />,
      },
      {
        path: 'scans/:scanId/results',
        element: <AssessmentResultsPage />,
      },
      {
        path: 'assessments/:assessmentId/findings',
        element: <FindingsPage />,
      },
      {
        path: 'assessments/:assessmentId/reports',
        element: <ReportsPage />,
      },
      {
        path: 'plans/:planId',
        element: <MigrationPlanPage />,
      },
      {
        path: 'compliance/:reportId',
        element: <CompliancePage />,
      },
    ],
  },
  {
    path: '*',
    element: <NotFoundPage />,
  },
])
