import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard    from './pages/Dashboard';
import AttackLab    from './pages/AttackLab';
import Chat         from './pages/Chat';
import QuarantineCenter from './pages/QuarantineCenter';
import { getHealth } from './api/sentinel';

const PAGE_META = {
  dashboard: { title: 'Dashboard',       subtitle: 'Real-time security telemetry' },
  attacklab:  { title: 'Attack Lab',      subtitle: 'Interactive security analysis pipeline' },
  chat:       { title: 'Secure Chat',     subtitle: 'Full-pipeline protected LLM proxy' },
  quarantine: { title: 'Quarantine Center', subtitle: 'Manage intercepted and quarantined requests' },
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
          </div>
        </div>
        <div className="page-content">
          <div style={{ display: page === 'dashboard' ? 'block' : 'none', height: '100%' }}>
            <Dashboard />
          </div>
          <div style={{ display: page === 'attacklab' ? 'block' : 'none', height: '100%' }}>
            <AttackLab />
          </div>
          <div style={{ display: page === 'chat' ? 'block' : 'none', height: '100%' }}>
            <Chat />
          </div>
          <div style={{ display: page === 'quarantine' ? 'block' : 'none', height: '100%' }}>
            <QuarantineCenter />
          </div>
        </div>
      </div>
    </div>
  );
}
