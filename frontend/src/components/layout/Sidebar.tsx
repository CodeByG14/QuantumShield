import { useState } from 'react'
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
  const [collapsed, setCollapsed] = useState(false)

  return (
    <aside
      className={`${
        collapsed ? 'w-20' : 'w-64'
      } bg-dark-secondary border-r border-dark-tertiary flex-shrink-0 transition-[width] duration-300 ease-in-out`}
    >
      <div className="h-full flex flex-col">
        {/* Logo/Brand */}
        <div
          className={`items-center border-b border-dark-tertiary py-4 ${
            collapsed
              ? 'grid grid-cols-[1fr_auto_1fr] px-2'
              : 'flex justify-between px-3'
          }`}
        >
          {collapsed && <span aria-hidden="true" />}
          <Link
            to="/"
            className={`flex min-w-0 items-center justify-center ${
              collapsed ? 'gap-0' : 'flex-1 gap-2'
            }`}
          >
            <svg
              className={`flex-shrink-0 transition-all duration-300 ${collapsed ? 'h-12 w-10' : 'h-[52px] w-12'}`}
              viewBox="82 10 84 100"
              role="img"
              aria-label="QuantumShield logo"
            >
              <image href={goldLogo} width="240" height="170" />
            </svg>
            <h1
              className={`flex-none overflow-hidden whitespace-nowrap text-lg font-bold text-text-0 transition-[width,opacity] duration-300 ${
                collapsed ? 'w-0 opacity-0' : 'w-auto opacity-100'
              }`}
            >
              QuantumShield
            </h1>
          </Link>
        </div>

        {/* Navigation */}
        <nav className={`flex-1 overflow-y-auto py-4 ${collapsed ? 'px-2' : 'px-3'}`} aria-label="Main navigation">
          <ul className="space-y-1">
            {navItems.map((item) => {
              const isActive = location.pathname === item.path
              return (
                <li key={item.path}>
                  <Link
                    to={item.path}
                    title={collapsed ? item.label : undefined}
                    aria-current={isActive ? 'page' : undefined}
                    className={`
                      flex items-center rounded-md py-2 text-sm font-medium
                      transition-colors duration-150
                      ${collapsed ? 'justify-center px-3' : 'gap-3 px-3'}
                      ${
                        isActive
                          ? 'bg-dark-accent text-dark-primary'
                          : 'text-text-1 hover:bg-dark-tertiary hover:text-text-0'
                      }
                    `}
                  >
                    <span className="flex-shrink-0">{item.icon}</span>
                    <span
                      className={`flex-none overflow-hidden whitespace-nowrap transition-[width,opacity] duration-300 ${
                        collapsed ? 'w-0 opacity-0' : 'w-auto opacity-100'
                      }`}
                    >
                      {item.label}
                    </span>
                  </Link>
                </li>
              )
            })}
          </ul>
        </nav>

        <div className={`flex py-2 ${collapsed ? 'justify-center' : 'justify-end px-4'}`}>
          <button
            type="button"
            onClick={() => setCollapsed((current) => !current)}
            className="flex h-8 w-8 items-center justify-center rounded-md text-text-2 transition-colors hover:bg-dark-tertiary hover:text-text-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent"
            aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
            aria-expanded={!collapsed}
            title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          >
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d={collapsed ? 'M9 5l7 7-7 7' : 'M15 5l-7 7 7 7'}
              />
            </svg>
          </button>
        </div>

        {/* Footer */}
        <div className={`border-t border-dark-tertiary py-4 text-center text-xs text-text-3 ${collapsed ? 'px-2' : 'px-4'}`}>
          {collapsed ? (
            <span title="QuantumShield. All rights reserved.">&copy;</span>
          ) : (
            <>
              &copy; {new Date().getFullYear()} QuantumShield.<br />All rights reserved.
            </>
          )}
        </div>
      </div>
    </aside>
  )
}
