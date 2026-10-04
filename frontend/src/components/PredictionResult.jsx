import React from 'react';
import { ShieldAlert, ShieldCheck, Activity, Target, TrendingUp } from 'lucide-react';

/**
 * PredictionResult – displays the ML prediction card.
 *
 * Props:
 *   result – the full API response from POST /api/predict
 */
export default function PredictionResult({ result }) {
  if (!result) return null;

  const isPhishing = result.prediction === 'PHISHING';
  const cls = isPhishing ? 'phishing' : 'legitimate';
  const confidencePct = (result.confidence * 100).toFixed(1);

  return (
    <div className={`result-card ${cls}`} role="region" aria-label="Prediction result">
      {/* Header */}
      <div className={`result-header ${cls}`}>
        <div className={`result-icon ${cls}`}>
          {isPhishing
            ? <ShieldAlert size={28} />
            : <ShieldCheck size={28} />}
        </div>
        <div>
          <div className={`result-prediction ${cls}`}>
            {isPhishing ? '⚠ PHISHING DETECTED' : '✓ LEGITIMATE'}
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>
            Model: <span style={{ color: 'var(--text-secondary)' }}>{result.model_used}</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2, fontFamily: 'JetBrains Mono, monospace' }}>
            {result.url_analyzed?.length > 60
              ? result.url_analyzed.slice(0, 60) + '…'
              : result.url_analyzed}
          </div>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="result-body">
        {/* Confidence */}
        <div className="result-metric">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 6 }}>
            <Activity size={14} color="var(--text-muted)" />
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
              Model Confidence
            </span>
          </div>
          <div className="result-metric-value">{confidencePct}%</div>
          <div className="confidence-bar-wrapper" style={{ marginTop: 8 }}>
            <div className="confidence-bar-track">
              <div
                className={`confidence-bar-fill ${cls}`}
                style={{ width: `${confidencePct}%` }}
              />
            </div>
          </div>
          <div className="result-metric-label" style={{ marginTop: 4 }}>Estimated confidence</div>
        </div>

        {/* Risk Score */}
        <div className="result-metric">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 6 }}>
            <Target size={14} color="var(--text-muted)" />
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
              Risk Score
            </span>
          </div>
          <div className="result-metric-value">
            {result.risk_score}{' '}
            <span style={{ fontSize: '1.2rem', color: 'var(--text-muted)' }}>/100</span>
          </div>
          <div className="result-metric-label" style={{ marginTop: 4 }}>Application risk score</div>
        </div>

        {/* Risk Level */}
        <div className="result-metric">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 6 }}>
            <TrendingUp size={14} color="var(--text-muted)" />
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
              Risk Level
            </span>
          </div>
          <div style={{ marginTop: 8 }}>
            <span className={`risk-badge ${result.risk_level}`}>
              {result.risk_level}
            </span>
          </div>
          <div className="result-metric-label" style={{ marginTop: 12 }}>Estimated risk category</div>
        </div>
      </div>
    </div>
  );
}
