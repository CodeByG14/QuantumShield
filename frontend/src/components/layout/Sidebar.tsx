import { Link, useLocation } from 'react-router-dom'
import goldLogo from '@/assets/lockup-gold.svg'

interface NavItem {
  label: string
  path: string
  icon: React.ReactNode
}

const navItems: NavItem[] = [
  {
    label: 'Dashboard',
    path: '/',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
      </svg>
    ),
  },
  {
    label: 'Projects',
    path: '/projects',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
      </svg>
    ),
  },
  {
    label: 'New Scan',
    path: '/scans/new',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
      </svg>
    ),
  },
]

export function Sidebar() {
  const location = useLocation()

  return (
    <aside className="w-64 bg-dark-secondary border-r border-dark-tertiary flex-shrink-0">
      <div className="h-full flex flex-col">
        {/* Logo/Brand */}
        <div className="px-6 py-4 border-b border-dark-tertiary">
          <Link to="/" className="flex items-center justify-center gap-3">
            <svg
              className="w-12 h-[52px] flex-shrink-0"
              viewBox="82 10 84 100"
              role="img"
              aria-label="QuantumShield logo"
            >
              <image href={goldLogo} width="240" height="170" />
            </svg>
            <h1 className="text-lg font-bold text-text-0">QuantumShield</h1>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 overflow-y-auto">
          <ul className="space-y-1">
            {navItems.map((item) => {
              const isActive = location.pathname === item.path
              return (
                <li key={item.path}>
                  <Link
                    to={item.path}
                    className={`
                      flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium
                      transition-colors duration-150
                      ${
                        isActive
                          ? 'bg-dark-accent text-dark-primary'
                          : 'text-text-1 hover:bg-dark-tertiary hover:text-text-0'
                      }
                    `}
                  >
                    {item.icon}
                    {item.label}
                  </Link>
                </li>
              )
            })}
          </ul>
        </nav>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-dark-tertiary text-xs text-text-3 text-center">
          &copy; {new Date().getFullYear()} QuantumShield.<br/>All rights reserved.    
        </div>
      </div>
    </aside>
  )
}
