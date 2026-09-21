import React from 'react';

const COLOR_MAP = {
  LOW:       'var(--col-low)',
  MODERATE:  'var(--col-moderate)',
  HIGH:      'var(--col-high)',
  VERY_HIGH: 'var(--col-very-high)',
  CRITICAL:  'var(--col-critical)',
};

const GRADIENT_MAP = {
  LOW:       'linear-gradient(135deg, #00ff9d, #00e5ff)',
  MODERATE:  'linear-gradient(135deg, #fbbf24, #f97316)',
  HIGH:      'linear-gradient(135deg, #f97316, #ff4d6d)',
  VERY_HIGH: 'linear-gradient(135deg, #ff4d6d, #e11d48)',
  CRITICAL:  'linear-gradient(135deg, #e11d48, #9f1239)',
};

export default function RiskMeter({ score, level }) {
  const pct = Math.min(100, Math.max(0, score ?? 0));
  const color = COLOR_MAP[level] ?? 'var(--accent-cyan)';
  const gradient = GRADIENT_MAP[level] ?? 'linear-gradient(135deg, var(--accent-cyan), var(--accent-green))';

  return (
    <div className="risk-meter-wrap">
      <div className="flex" style={{ justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 4 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Risk Score
        </span>
        <span style={{ fontSize: 22, fontWeight: 800, color, fontFamily: 'var(--font-mono)' }}>
          {pct.toFixed(1)}
        </span>
      </div>
      <div className="risk-bar-track">
        <div
          className="risk-bar-fill"
          style={{ width: `${pct}%`, background: gradient, '--bar-color': color }}
        />
      </div>
      <div className="risk-labels">
        <span>0 — Safe</span>
        <span>50 — High</span>
        <span>100 — Critical</span>
      </div>
    </div>
  );
}
