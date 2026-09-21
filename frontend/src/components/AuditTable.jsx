import React from 'react';
import { DecisionBadge, RiskBadge } from './ThreatBadge';

function fmtTime(isoStr) {
  if (!isoStr) return '—';
  try { return new Date(isoStr).toLocaleTimeString(); } catch { return isoStr; }
}

export default function AuditTable({ logs, loading }) {
  if (loading) {
    return (
      <div className="table-wrap">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="skeleton" style={{ height: 36, marginBottom: 6, borderRadius: 6 }} />
        ))}
      </div>
    );
  }
  if (!logs?.length) {
    return (
      <div className="empty-state">
        <span className="icon">📋</span>
        <p>No audit logs yet. Send a request through the Attack Lab or Chat to generate logs.</p>
      </div>
    );
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Decision</th>
            <th>Risk</th>
            <th>Risk Level</th>
            <th>Injection</th>
            <th>PII</th>
            <th>Secrets</th>
            <th>Toxicity</th>
            <th>Latency</th>
            <th>Session</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, i) => (
            <tr key={log.request_id ?? i}>
              <td className="mono" style={{ color: 'var(--text-muted)' }}>{fmtTime(log.timestamp)}</td>
              <td><DecisionBadge decision={log.decision} /></td>
              <td className="mono">{log.risk_score?.toFixed(1) ?? '—'}</td>
              <td><RiskBadge level={log.risk_level} /></td>
              <td style={{ color: log.injection_detected ? 'var(--col-block)' : 'var(--text-muted)' }}>
                {log.injection_detected ? `⚡ ${log.injection_category ?? 'Yes'}` : '—'}
              </td>
              <td style={{ color: log.pii_detected ? 'var(--col-sanitize)' : 'var(--text-muted)' }}>
                {log.pii_detected ? '👤 Yes' : '—'}
              </td>
              <td style={{ color: log.secrets_detected ? 'var(--col-block)' : 'var(--text-muted)' }}>
                {log.secrets_detected ? '🔑 Yes' : '—'}
              </td>
              <td style={{ color: log.toxicity_detected ? 'var(--col-block)' : 'var(--text-muted)' }}>
                {log.toxicity_detected ? '☢️ Yes' : '—'}
              </td>
              <td className="mono">{log.total_latency_ms?.toFixed(1) ?? '—'}ms</td>
              <td className="mono truncate" style={{ maxWidth: 100, color: 'var(--text-muted)' }}>
                {log.session_id?.slice(0, 8) ?? '—'}…
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
