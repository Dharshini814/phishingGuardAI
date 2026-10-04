import React from 'react';
import {
  LayoutDashboard,
  ScanLine,
  History,
  BarChart3,
  Info,
  Shield,
} from 'lucide-react';

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'scanner', label: 'URL Scanner', icon: ScanLine },
  { id: 'history', label: 'Analysis History', icon: History },
  { id: 'performance', label: 'Model Performance', icon: BarChart3 },
  { id: 'about', label: 'About', icon: Info },
];

export default function Sidebar({ activePage, onNavigate, backendStatus, sidebarOpen }) {
  return (
    <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon">
          <Shield size={22} color="#fff" />
        </div>
        <div className="sidebar-logo-text">
          <span className="sidebar-logo-title">PhishGuard AI</span>
          <span className="sidebar-logo-subtitle">AI-Powered Detection</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <span className="sidebar-section-label">Navigation</span>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <div
              key={item.id}
              id={`nav-${item.id}`}
              className={`nav-item ${activePage === item.id ? 'active' : ''}`}
              onClick={() => onNavigate(item.id)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && onNavigate(item.id)}
            >
              <Icon size={18} className="nav-icon" />
              <span>{item.label}</span>
            </div>
          );
        })}
      </nav>

      {/* Footer Status */}
      <div className="sidebar-footer">
        <div className="sidebar-status">
          <div
            className={`status-dot ${
              backendStatus === 'online' ? '' :
              backendStatus === 'loading' ? 'loading' : 'offline'
            }`}
          />
          <span>
            Backend:{' '}
            {backendStatus === 'online'
              ? 'Connected'
              : backendStatus === 'loading'
              ? 'Connecting...'
              : 'Offline'}
          </span>
        </div>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 8 }}>
          v1.0.0 · localhost:8000
        </div>
      </div>
    </aside>
  );
}
