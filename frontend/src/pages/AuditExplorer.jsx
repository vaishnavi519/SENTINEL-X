import React, { useState, useEffect, useCallback } from 'react';
import { getAuditLogs } from '../api/sentinel';
import AuditTable from '../components/AuditTable';

const DECISIONS = ['', 'ALLOW', 'SANITIZE', 'QUARANTINE', 'BLOCK'];

export default function AuditExplorer() {
  const [logs,      setLogs]      = useState([]);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState(null);
  const [decision,  setDecision]  = useState('');
  const [sessionId, setSessionId] = useState('');
  const [limit,     setLimit]     = useState(50);
  const [offset,    setOffset]    = useState(0);
  const [total,     setTotal]     = useState(0);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAuditLogs({
        limit,
        offset,
        decision:   decision || undefined,
        session_id: sessionId || undefined,
      });
      setLogs(res.data ?? []);
      setTotal(res.count ?? 0);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [limit, offset, decision, sessionId]);

  useEffect(() => { fetch(); }, [fetch]);

  const reset = () => {
    setDecision('');
    setSessionId('');
    setOffset(0);
    setLimit(50);
  };

  return (
    <div className="fade-in">
      {/* Filters */}
      <div className="card mb-6">
        <div className="card-header">
          <span className="card-title">🔎 Filters</span>
          <button className="btn btn-ghost btn-sm" onClick={reset}>Reset</button>
        </div>
        <div className="card-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--sp-4)' }}>
            <div>
              <label>Decision</label>
              <select value={decision} onChange={e => { setDecision(e.target.value); setOffset(0); }}>
                {DECISIONS.map(d => <option key={d} value={d}>{d || 'All'}</option>)}
              </select>
            </div>
            <div>
              <label>Session ID</label>
              <input
                type="text"
                value={sessionId}
                onChange={e => { setSessionId(e.target.value); setOffset(0); }}
                placeholder="Filter by session UUID…"
              />
            </div>
            <div>
              <label>Rows per page</label>
              <select value={limit} onChange={e => { setLimit(Number(e.target.value)); setOffset(0); }}>
                {[10, 25, 50, 100, 200].map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
          </div>
        </div>
      </div>

      {error && <div className="error-banner mb-4">⚠️ {error}</div>}

      {/* Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">📋 Security Audit Trail</span>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {logs.length} shown
            </span>
            <button className="btn btn-ghost btn-sm" onClick={fetch}>↻ Refresh</button>
          </div>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          <AuditTable logs={logs} loading={loading} />
        </div>
        {/* Pagination */}
        {logs.length > 0 && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-4) var(--sp-6)', borderTop: '1px solid var(--border)' }}>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
            >
              ← Previous
            </button>
            <span style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Showing {offset + 1}–{offset + logs.length}
            </span>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setOffset(offset + limit)}
              disabled={logs.length < limit}
            >
              Next →
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
