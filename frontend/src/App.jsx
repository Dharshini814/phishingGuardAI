import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import History from './pages/History';
import ModelPerformance from './pages/ModelPerformance';
import About from './pages/About';
import { checkHealth } from './api/api';

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [backendStatus, setBackendStatus] = useState('loading');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Check backend health on mount and periodically
  useEffect(() => {
    async function checkBackend() {
      try {
        await checkHealth();
        setBackendStatus('online');
      } catch {
        setBackendStatus('offline');
      }
    }

    checkBackend();
    const interval = setInterval(checkBackend, 30000); // every 30s
    return () => clearInterval(interval);
  }, []);

  function renderPage() {
    switch (activePage) {
      case 'dashboard':   return <Dashboard />;
      case 'scanner':     return <Scanner />;
      case 'history':     return <History />;
      case 'performance': return <ModelPerformance />;
      case 'about':       return <About />;
      default:            return <Dashboard />;
    }
  }

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <Sidebar
        activePage={activePage}
        onNavigate={(page) => {
          setActivePage(page);
          setSidebarOpen(false); // close on mobile after navigation
        }}
        backendStatus={backendStatus}
        sidebarOpen={sidebarOpen}
      />

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.6)',
            zIndex: 'calc(var(--z-sidebar) - 1)',
            backdropFilter: 'blur(2px)',
          }}
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Main content area */}
      <main className="main-content">
        {renderPage()}
      </main>
    </div>
  );
}
