import React from 'react';

const DECISION_ICONS = { ALLOW: '✅', SANITIZE: '🔧', QUARANTINE: '🔒', BLOCK: '🛑', TERMINATE_SESSION: '💀' };

export function DecisionBadge({ decision }) {
  if (!decision) return null;
  const cls = `badge badge-${decision.toLowerCase()}`;
  return <span className={cls}>{DECISION_ICONS[decision] || ''} {decision}</span>;
}

const RISK_ICONS = { LOW: '🟢', MODERATE: '🟡', HIGH: '🟠', VERY_HIGH: '🔴', CRITICAL: '💀', TERMINATED: '☠️' };

export function RiskBadge({ level }) {
  if (!level) return null;
  const cls = `badge badge-${level.toLowerCase()}`;
  return <span className={cls}>{RISK_ICONS[level] || ''} {level.replace('_', ' ')}</span>;
}

export function ThreatTag({ threat }) {
  return <span className="tag">{threat}</span>;
}
