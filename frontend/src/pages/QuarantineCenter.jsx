import React, { useState, useEffect, useCallback } from 'react';
import { getQuarantineLogs, actionQuarantine } from '../api/sentinel';
import { ThreatTag } from '../components/ThreatBadge';

export default function QuarantineCenter() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getQuarantineLogs();
      setLogs(res.data || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const handleAction = async (qId, sessionId, action) => {
    try {
      await actionQuarantine(qId, action);
      fetchLogs();
      if (action === 'REJECT') {
        window.dispatchEvent(new CustomEvent('quarantine-rejected', { detail: { sessionId } }));
      } else {
        window.dispatchEvent(new CustomEvent('quarantine-released', { detail: { sessionId } }));
      }
    } catch (e) {
      alert("Error: " + e.message);
    }
  };

  return (
    <div className="fade-in">
      {error && <div className="error-banner mb-4">⚠️ {error}</div>}

      <div className="card">
        <div className="card-header">
          <span className="card-title">🛡️ Quarantine Center</span>
          <button className="btn btn-ghost btn-sm" onClick={fetchLogs}>↻ Refresh</button>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {loading ? (
            <div style={{ padding: 'var(--sp-4)', color: 'var(--text-muted)' }}>Loading...</div>
          ) : logs.length === 0 ? (
            <div className="empty-state" style={{ padding: 'var(--sp-6)' }}>
              <span className="icon">✅</span>
              <p>No requests are currently in quarantine.</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {logs.map((log) => (
                <div key={log.q_id} style={{ padding: 'var(--sp-4)', borderBottom: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--sp-2)' }}>
                    <div>
                      <span style={{ fontSize: 14, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{log.q_id}</span>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 8 }}>Session: {log.session_id}</span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{new Date(log.timestamp).toLocaleString()}</div>
                  </div>
                  
                  <div style={{ marginBottom: 'var(--sp-3)', display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-amber)' }}>RISK: {log.risk_score}</span>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>•</span>
                    <span style={{ fontSize: 11, color: 'var(--col-quarantine)' }}>{log.status}</span>
                  </div>

                  <div style={{ marginBottom: 'var(--sp-3)' }}>
                    {log.threats && log.threats.map((t, i) => (
                      <ThreatTag key={i} threat={t.name} />
                    ))}
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.3)', padding: 'var(--sp-3)', borderRadius: 'var(--r-md)', marginBottom: 'var(--sp-3)', fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', maxHeight: 150, overflowY: 'auto' }}>
                    {log.input_text}
                  </div>

                  <div style={{ fontSize: 11, color: 'var(--col-quarantine)', marginBottom: 'var(--sp-3)' }}>
                    Reason: {log.decision_reason}
                  </div>

                  {log.status === "QUARANTINED" && (
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button className="btn btn-ghost btn-sm" style={{ color: 'var(--col-allow)' }} onClick={() => handleAction(log.q_id, log.session_id, 'RELEASE')}>✓ RELEASE</button>
                      <button className="btn btn-ghost btn-sm" style={{ color: 'var(--col-block)' }} onClick={() => handleAction(log.q_id, log.session_id, 'REJECT')}>✕ REJECT</button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
