import React from 'react';
import { DecisionBadge, RiskBadge, ThreatTag } from './ThreatBadge';

export default function ReceiptViewer({ receipt }) {
  if (!receipt) return null;

  const sig = receipt.explanation.match(/\[Sig:(.*?)\]/)?.[1];
  const cleanExplanation = receipt.explanation.replace(/\s*\[Sig:.*?\]/, '');

  return (
    <div className="receipt fade-in">
      <div className="receipt-row">
        <span className="receipt-key">🆔 Request ID</span>
        <span className="receipt-val mono">{receipt.request_id}</span>
      </div>
      <div className="receipt-row">
        <span className="receipt-key">🕐 Timestamp</span>
        <span className="receipt-val mono">{new Date(receipt.timestamp).toLocaleString()}</span>
      </div>
      <div className="receipt-row">
        <span className="receipt-key">⚖️ Decision</span>
        <span className="receipt-val"><DecisionBadge decision={receipt.decision} /></span>
      </div>
      <div className="receipt-row">
        <span className="receipt-key">📊 Risk Score</span>
        <span className="receipt-val mono">{receipt.risk_score?.toFixed(2)} / 100</span>
      </div>
      <div className="receipt-row">
        <span className="receipt-key">🎚️ Risk Level</span>
        <span className="receipt-val"><RiskBadge level={receipt.risk_level} /></span>
      </div>
      <div className="receipt-row">
        <span className="receipt-key">⚠️ Threats Detected</span>
        <span className="receipt-val">
          {receipt.threats_detected?.length > 0
            ? receipt.threats_detected.map((t, i) => <ThreatTag key={i} threat={t} />)
            : <span style={{ color: 'var(--col-allow)' }}>None</span>
          }
        </span>
      </div>
      <div className="receipt-row">
        <span className="receipt-key">📝 Triggered Policies</span>
        <span className="receipt-val">
          {receipt.triggered_policies?.length > 0
            ? receipt.triggered_policies.join(', ')
            : <span style={{ color: 'var(--col-allow)' }}>None</span>
          }
        </span>
      </div>
      <div className="receipt-row">
        <span className="receipt-key">🔍 PII Detected</span>
        <span className="receipt-val" style={{ color: receipt.pii_detected ? 'var(--col-sanitize)' : 'var(--col-allow)' }}>
          {receipt.pii_detected ? 'Yes' : 'No'}
        </span>
      </div>
      <div className="receipt-row">
        <span className="receipt-key">🔑 Secrets Detected</span>
        <span className="receipt-val" style={{ color: receipt.secrets_detected ? 'var(--col-block)' : 'var(--col-allow)' }}>
          {receipt.secrets_detected ? 'Yes' : 'No'}
        </span>
      </div>
      <div className="receipt-row">
        <span className="receipt-key">⏱️ Latency</span>
        <span className="receipt-val mono">{receipt.latency_ms?.toFixed(2)} ms</span>
      </div>
      <div className="receipt-row" style={{ border: 'none' }}>
        <span className="receipt-key">📋 Explanation</span>
        <span className="receipt-val" style={{ color: 'var(--text-primary)', lineHeight: 1.6 }}>{cleanExplanation}</span>
      </div>
      {sig && (
        <div className="receipt-sig">
          🔐 SHA-256 Signature: {sig.trim()}
        </div>
      )}
    </div>
  );
}
