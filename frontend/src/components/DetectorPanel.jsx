import React, { useState } from 'react';

const DETECTOR_CONFIG = {
  injection: {
    label: 'Prompt Injection',
    icon: '💉',
    color: 'var(--col-block)',
    getStatus: (d) => d?.detected ? `${d.category} — ${d.severity}` : 'CLEAN',
    getConf: (d) => d?.confidence ?? 0,
    getEvidence: (d) => d?.evidence?.slice(0, 3).join('\n') ?? '',
  },
  pii: {
    label: 'PII Detector',
    icon: '👤',
    color: 'var(--col-sanitize)',
    getStatus: (d) => d?.detected ? d.pii_types?.join(', ') || 'PII found' : 'CLEAN',
    getConf: (d) => d?.detected ? 0.9 : 0,
    getEvidence: (d) => d?.detected ? `${d.count} entity/entities detected` : '',
  },
  secrets: {
    label: 'Secret Detector',
    icon: '🔑',
    color: 'var(--col-block)',
    getStatus: (d) => d?.detected ? d.secret_types?.join(', ') || 'Secret found' : 'CLEAN',
    getConf: (d) => d?.detected ? 0.95 : 0,
    getEvidence: (d) => d?.detected ? `${d.count} secret(s) detected` : '',
  },
  toxicity: {
    label: 'Toxicity Detector',
    icon: '☢️',
    color: 'var(--col-block)',
    getStatus: (d) => d?.detected ? `${d.category ?? 'Toxic'} — ${d.severity}` : 'CLEAN',
    getConf: (d) => d?.confidence ?? 0,
    getEvidence: (d) => d?.detected ? `Severity: ${d.severity}` : '',
  },
  intent: {
    label: 'Intent Analyzer',
    icon: '🎯',
    color: 'var(--col-quarantine)',
    getStatus: (d) => d?.category ?? 'UNKNOWN',
    getConf: (d) => d?.confidence ?? 0,
    getEvidence: (d) => d?.is_suspicious ? '⚠ Suspicious intent detected' : 'Intent appears benign',
  },
  normalization: {
    label: 'Input Normalizer',
    icon: '🔬',
    color: 'var(--accent-cyan)',
    getStatus: (d) => d?.suspicious ? `SUSPICIOUS — ${d.flags?.join(', ')}` : 'CLEAN',
    getConf: (d) => d?.suspicious ? 0.8 : 0,
    getEvidence: (d) => d?.flags?.length ? d.flags.join(', ') : d?.decoded_variants_checked ? `${d.decoded_variants_checked} variants checked` : 'No obfuscation detected',
  },
};

function SingleDetectorPanel({ type, data }) {
  const cfg = DETECTOR_CONFIG[type];
  if (!cfg) return null;
  const detected = type === 'injection' ? data?.detected : type === 'normalization' ? data?.suspicious : data?.detected;
  const status = cfg.getStatus(data);
  const conf = cfg.getConf(data);
  const evidence = cfg.getEvidence(data);

  return (
    <div className={`detector-panel${detected ? ' detected' : ''} fade-in`}>
      <div className="detector-header">
        <span className="detector-name">{cfg.icon} {cfg.label}</span>
        <span style={{ fontSize: 11, color: detected ? cfg.color : 'var(--col-allow)', fontWeight: 700 }}>
          {detected ? '● FLAGGED' : '● CLEAN'}
        </span>
      </div>
      <div className="detector-body">
        <div className="detector-status">
          <span>{status}</span>
        </div>
        {detected && (
          <div className="detector-confidence">
            <div className="conf-bar-track">
              <div
                className="conf-bar-fill"
                style={{
                  width: `${conf * 100}%`,
                  background: detected
                    ? `linear-gradient(90deg, ${cfg.color}, rgba(255,255,255,0.5))`
                    : 'linear-gradient(90deg, var(--accent-cyan), var(--accent-green))',
                }}
              />
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)' }}>
              {(conf * 100).toFixed(0)}%
            </span>
          </div>
        )}
        {evidence && (
          <div className="detector-evidence">{evidence}</div>
        )}
        {data?.latency_ms !== undefined && (
          <div className="detector-latency">{data.latency_ms.toFixed(2)} ms</div>
        )}
      </div>
    </div>
  );
}

export default function DetectorPanel({ analysis }) {
  if (!analysis) return null;
  return (
    <div className="detector-grid">
      <SingleDetectorPanel type="normalization" data={analysis.normalization} />
      <SingleDetectorPanel type="injection"    data={analysis.injection} />
      <SingleDetectorPanel type="pii"          data={analysis.pii} />
      <SingleDetectorPanel type="secrets"      data={analysis.secrets} />
      <SingleDetectorPanel type="toxicity"     data={analysis.toxicity} />
      <SingleDetectorPanel type="intent"       data={analysis.intent} />
    </div>
  );
}
