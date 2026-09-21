import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Chart, ArcElement, Tooltip, Legend, DoughnutController } from 'chart.js';
import { getAuditStats, getAuditLogs } from '../api/sentinel';
import AuditTable from '../components/AuditTable';
import { DecisionBadge, RiskBadge } from '../components/ThreatBadge';

Chart.register(ArcElement, Tooltip, Legend, DoughnutController);

function StatCard({ icon, value, label, color }) {
  return (
    <div className="stat-card" style={{ '--accent-color': color }}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value">{value ?? '—'}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function ThreatDonut({ data }) {
  const canvasRef = useRef(null);
  const chartRef  = useRef(null);

  useEffect(() => {
    if (!canvasRef.current || !data) return;
    if (chartRef.current) { chartRef.current.destroy(); }

    const tc = data.threat_counts;
    chartRef.current = new Chart(canvasRef.current, {
      type: 'doughnut',
      data: {
        labels: ['Prompt Injection', 'PII Leakage', 'Secret Exposure', 'Toxicity & Harm'],
        datasets: [{
          data: [tc.prompt_injection, tc.pii_leakage, tc.secret_exposure, tc.toxicity_and_harm],
          backgroundColor: ['rgba(255,77,109,0.75)', 'rgba(251,191,36,0.75)', 'rgba(168,85,247,0.75)', 'rgba(249,115,22,0.75)'],
          borderColor:     ['rgba(255,77,109,0.3)',  'rgba(251,191,36,0.3)',  'rgba(168,85,247,0.3)',  'rgba(249,115,22,0.3)'],
          borderWidth: 1,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        cutout: '70%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#94a3b8',
              font: { size: 11, family: 'Inter' },
              padding: 12,
              boxWidth: 12,
            },
          },
          tooltip: {
            backgroundColor: 'rgba(5,9,18,0.95)',
            borderColor: 'rgba(0,229,255,0.3)',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
          },
        },
      },
    });

    return () => { if (chartRef.current) { chartRef.current.destroy(); chartRef.current = null; } };
  }, [data]);

  return (
    <div className="chart-wrap">
      <canvas ref={canvasRef} />
    </div>
  );
}

function DecisionDonut({ data }) {
  const canvasRef = useRef(null);
  const chartRef  = useRef(null);

  useEffect(() => {
    if (!canvasRef.current || !data) return;
    if (chartRef.current) { chartRef.current.destroy(); }

    const d = data.decisions;
    chartRef.current = new Chart(canvasRef.current, {
      type: 'doughnut',
      data: {
        labels: ['ALLOW', 'SANITIZE', 'QUARANTINE', 'BLOCK'],
        datasets: [{
          data: [d.ALLOW, d.SANITIZE, d.QUARANTINE, d.BLOCK],
          backgroundColor: ['rgba(0,255,157,0.7)', 'rgba(251,191,36,0.7)', 'rgba(249,115,22,0.7)', 'rgba(255,77,109,0.7)'],
          borderColor:     ['rgba(0,255,157,0.2)',  'rgba(251,191,36,0.2)',  'rgba(249,115,22,0.2)',  'rgba(255,77,109,0.2)'],
          borderWidth: 1,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        cutout: '70%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#94a3b8', font: { size: 11, family: 'Inter' }, padding: 12, boxWidth: 12 },
          },
          tooltip: {
            backgroundColor: 'rgba(5,9,18,0.95)',
            borderColor: 'rgba(0,229,255,0.3)',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
          },
        },
      },
    });

    return () => { if (chartRef.current) { chartRef.current.destroy(); chartRef.current = null; } };
  }, [data]);

  return (
    <div className="chart-wrap">
      <canvas ref={canvasRef} />
    </div>
  );
}

export default function Dashboard() {
  const [stats,      setStats]     = useState(null);
  const [logs,       setLogs]      = useState([]);
  const [loadStats,  setLoadStats] = useState(true);
  const [loadLogs,   setLoadLogs]  = useState(true);
  const [error,      setError]     = useState(null);

  const fetchAll = useCallback(async () => {
    try {
      setLoadStats(true);
      setLoadLogs(true);
      const [s, l] = await Promise.all([getAuditStats(), getAuditLogs({ limit: 10 })]);
      setStats(s);
      setLogs(l.data ?? []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoadStats(false);
      setLoadLogs(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  return (
    <div className="fade-in">
      {error && (
        <div className="error-banner mb-6">
          ⚠️ {error} — is the backend running on localhost:8000?
        </div>
      )}

      {/* Stat cards */}
      <div className="stat-cards">
        <StatCard icon="📡" value={stats?.total_requests}                       label="Total Requests"   color="var(--accent-cyan)" />
        <StatCard icon="✅" value={stats?.decisions?.ALLOW}                     label="Allowed"          color="var(--col-allow)" />
        <StatCard icon="🔧" value={stats?.decisions?.SANITIZE}                  label="Sanitized"        color="var(--col-sanitize)" />
        <StatCard icon="🔒" value={stats?.decisions?.QUARANTINE}                label="Quarantined"      color="var(--col-quarantine)" />
        <StatCard icon="🛑" value={stats?.decisions?.BLOCK}                     label="Blocked"          color="var(--col-block)" />
        <StatCard icon="⏱️" value={stats?.performance?.avg_security_latency_ms !== undefined ? `${stats.performance.avg_security_latency_ms}ms` : undefined} label="Avg Latency" color="var(--accent-purple)" />
        <StatCard icon="📊" value={stats?.performance?.avg_risk_score !== undefined ? stats.performance.avg_risk_score.toFixed(1) : undefined} label="Avg Risk Score" color="var(--accent-amber)" />
      </div>

      {/* Charts row */}
      <div className="grid-2 mb-6">
        <div className="card">
          <div className="card-header"><span className="card-title">⚠️ Threat Distribution</span></div>
          <div className="card-body">
            {stats ? <ThreatDonut data={stats} /> : <div className="skeleton" style={{ height: 200 }} />}
          </div>
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">⚖️ Decision Breakdown</span></div>
          <div className="card-body">
            {stats ? <DecisionDonut data={stats} /> : <div className="skeleton" style={{ height: 200 }} />}
          </div>
        </div>
      </div>

      {/* Threat counts */}
      {stats && (
        <div className="card mb-6">
          <div className="card-header">
            <span className="card-title">🔍 Threat Breakdown</span>
          </div>
          <div className="card-body">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 'var(--sp-4)' }}>
              {[
                { label: 'Prompt Injection', value: stats.threat_counts?.prompt_injection, color: 'var(--col-block)' },
                { label: 'PII Leakage',      value: stats.threat_counts?.pii_leakage,      color: 'var(--col-sanitize)' },
                { label: 'Secret Exposure',  value: stats.threat_counts?.secret_exposure,  color: 'var(--accent-purple)' },
                { label: 'Toxicity & Harm',  value: stats.threat_counts?.toxicity_and_harm,color: 'var(--col-quarantine)' },
              ].map(({ label, value, color }) => (
                <div key={label} style={{ padding: 'var(--sp-4)', background: 'rgba(0,0,0,0.20)', borderRadius: 'var(--r-md)', borderLeft: `3px solid ${color}` }}>
                  <div style={{ fontSize: 24, fontWeight: 800, color, fontFamily: 'var(--font-mono)', marginBottom: 4 }}>{value ?? 0}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Recent logs */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">📋 Recent Security Events</span>
          <button className="btn btn-ghost btn-sm" onClick={fetchAll}>↻ Refresh</button>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          <AuditTable logs={logs} loading={loadLogs} />
        </div>
      </div>
    </div>
  );
}
