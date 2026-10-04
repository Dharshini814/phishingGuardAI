import React from 'react';
import { AlertTriangle, CheckCircle, Info } from 'lucide-react';

/**
 * RiskIndicator – shows detected URL warning signals and positive signals.
 *
 * Props:
 *   indicators     – list of warning strings
 *   positiveSignals – list of positive signal strings
 *   explanation    – natural language explanation string
 */
export default function RiskIndicator({ indicators, positiveSignals, explanation }) {
  const hasWarnings = indicators && indicators.length > 0;
  const hasPositives = positiveSignals && positiveSignals.length > 0;

  if (!hasWarnings && !hasPositives && !explanation) return null;

  return (
    <div className="indicators-section" style={{ background: 'var(--bg-card)', borderTop: '1px solid var(--border-primary)' }}>
      <h3 className="indicators-title">Detected URL Indicators</h3>

      {hasWarnings && (
        <div className="indicator-list">
          {indicators.map((item, i) => (
            <div key={i} className="indicator-item warning">
              <AlertTriangle size={14} />
              {item}
            </div>
          ))}
        </div>
      )}

      {hasPositives && (
        <div className="indicator-list" style={{ marginTop: hasWarnings ? 12 : 0 }}>
          {positiveSignals.map((item, i) => (
            <div key={i} className="indicator-item positive">
              <CheckCircle size={14} />
              {item}
            </div>
          ))}
        </div>
      )}

      {!hasWarnings && !hasPositives && (
        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          No specific indicators were detected.
        </p>
      )}

      {/* Disclaimer */}
      <div className="indicator-disclaimer">
        <Info size={12} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
        These characteristics are signals used by the system and do not independently prove
        that a website is malicious or safe. Always verify through multiple security sources.
      </div>

      {/* Explanation */}
      {explanation && (
        <div className="explanation-box" style={{ marginTop: 12 }}>
          <strong style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Analysis Summary: </strong>
          {explanation}
        </div>
      )}
    </div>
  );
}
