import React from 'react';
import { Clock, ShieldAlert, ShieldCheck } from 'lucide-react';

/**
 * HistoryTable – displays scan history in a professional table.
 *
 * Props:
 *   records – array of scan history records
 */
export default function HistoryTable({ records }) {
  if (!records || records.length === 0) {
    return (
      <div className="empty-state">
        <Clock className="empty-state-icon" size={64} color="var(--text-muted)" />
        <div className="empty-state-title">No scan history yet</div>
        <p className="empty-state-text">
          Analyzed URLs will appear here. Use the URL Scanner to get started.
        </p>
      </div>
    );
  }

  return (
    <div className="history-table-wrapper">
      <table className="history-table" role="table">
        <thead>
          <tr>
            <th>#</th>
            <th>URL Analyzed</th>
            <th>Prediction</th>
            <th>Confidence</th>
            <th>Risk Score</th>
            <th>Risk Level</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {records.map((record, index) => (
            <tr key={record.id}>
              <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                {index + 1}
              </td>
              <td className="url-cell" title={record.url}>
                {record.url}
              </td>
              <td>
                <span className={`prediction-badge ${record.prediction}`}>
                  {record.prediction === 'PHISHING'
                    ? <ShieldAlert size={10} />
                    : <ShieldCheck size={10} />}
                  {record.prediction}
                </span>
              </td>
              <td style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                {(record.confidence * 100).toFixed(1)}%
              </td>
              <td style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                <span
                  style={{
                    color:
                      record.risk_score > 60
                        ? 'var(--color-red)'
                        : record.risk_score > 30
                        ? 'var(--color-amber)'
                        : 'var(--color-green)',
                  }}
                >
                  {record.risk_score}/100
                </span>
              </td>
              <td>
                <span className={`risk-badge ${record.risk_level}`}>
                  {record.risk_level}
                </span>
              </td>
              <td className="timestamp-cell">
                {new Date(record.timestamp).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
