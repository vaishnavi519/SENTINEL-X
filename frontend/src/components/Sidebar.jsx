import React, { useState } from 'react';

const NAV_ITEMS = [
  { id: 'dashboard',    icon: '⬡',  label: 'Dashboard' },
  { id: 'attacklab',   icon: '⚡',  label: 'Attack Lab' },
  { id: 'chat',        icon: '💬',  label: 'Secure Chat' },
  { id: 'audit',       icon: '📋',  label: 'Audit Explorer' },
];

export default function Sidebar({ activePage, onNavigate, backendStatus }) {
  return (
    <nav className="sidebar">
      <div className="sidebar-logo">
        <h1>SENTINEL-X</h1>
        <p>AI Security Middleware</p>
      </div>

      <span className="nav-section">Navigation</span>
      {NAV_ITEMS.map(item => (
        <button
          key={item.id}
          className={`nav-item${activePage === item.id ? ' active' : ''}`}
          onClick={() => onNavigate(item.id)}
        >
          <span className="nav-icon">{item.icon}</span>
          {item.label}
        </button>
      ))}

      <div className="sidebar-status">
        <div className="flex gap-2" style={{ alignItems: 'center', marginBottom: 6 }}>
          <span className="status-dot" style={{ background: backendStatus === 'ok' ? 'var(--col-allow)' : backendStatus === 'degraded' ? 'var(--col-sanitize)' : 'var(--col-block)', boxShadow: `0 0 8px ${backendStatus === 'ok' ? 'var(--col-allow)' : 'var(--col-block)'}` }} />
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            Backend {backendStatus ?? '…'}
          </span>
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          localhost:8000
        </div>
      </div>
    </nav>
  );
}
