
import React from 'react';

const NAV_ITEMS = [
  { id: 'dashboard',   icon: '⬡',  label: 'Dashboard' },
  { id: 'attacklab',   icon: '⚡',  label: 'Attack Lab' },
  { id: 'chat',        icon: '💬',  label: 'Secure Chat' },
  { id: 'quarantine',  icon: '🛡️', label: 'Quarantine Center' },
  { id: 'documents',   icon: '📄',  label: 'Document Scanner' },
];

export default function Sidebar({
  activePage,
  onNavigate,
  backendStatus,
}) {
  return (
    <nav className="sidebar">
      <div className="sidebar-logo">
        <h1>SENTINEL-X</h1>
        <p>AI Security Middleware</p>
      </div>

      <span className="nav-section">Navigation</span>

      {NAV_ITEMS.map((item) => (
        <button
          key={item.id}
          type="button"
          className={`nav-item${
            activePage === item.id ? ' active' : ''
          }`}
          onClick={() => onNavigate(item.id)}
        >
          <span className="nav-icon">{item.icon}</span>
          {item.label}
        </button>
      ))}
    </nav>
  );
}
