import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard    from './pages/Dashboard';
import AttackLab    from './pages/AttackLab';
import Chat         from './pages/Chat';
import AuditExplorer from './pages/AuditExplorer';
import { getHealth } from './api/sentinel';

const PAGE_META = {
  dashboard: { title: 'Dashboard',       subtitle: 'Real-time security telemetry' },
  attacklab:  { title: 'Attack Lab',      subtitle: 'Interactive security analysis pipeline' },
  chat:       { title: 'Secure Chat',     subtitle: 'Full-pipeline protected LLM proxy' },
  audit:      { title: 'Audit Explorer',  subtitle: 'Forensic security event trail' },
};

export default function App() {
  const [page,          setPage]         = useState('dashboard');
  const [backendStatus, setBackendStatus] = useState(null);

  useEffect(() => {
    getHealth()
      .then(h => setBackendStatus(h.status))
      .catch(() => setBackendStatus('error'));
  }, []);

  const meta = PAGE_META[page] ?? PAGE_META.dashboard;

  return (
    <div className="app-shell">
      <Sidebar
        activePage={page}
        onNavigate={setPage}
        backendStatus={backendStatus}
      />
      <div className="main-area">
        <div className="topbar">
          <div>
            <div className="topbar-title">{meta.title}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{meta.subtitle}</div>
          </div>
          <div className="topbar-meta">
            SENTINEL-X v0.1.0 · {new Date().toLocaleDateString()}
          </div>
        </div>
        <div className="page-content">
          {page === 'dashboard' && <Dashboard />}
          {page === 'attacklab'  && <AttackLab />}
          {page === 'chat'       && <Chat />}
          {page === 'audit'      && <AuditExplorer />}
        </div>
      </div>
    </div>
  );
}
