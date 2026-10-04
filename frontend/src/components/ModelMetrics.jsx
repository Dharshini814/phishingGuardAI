import React from 'react';
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar,
  ResponsiveContainer, Tooltip,
} from 'recharts';

const COLORS = {
  'Logistic Regression': '#3b82f6',
  'Decision Tree': '#f59e0b',
  'Random Forest': '#22c55e',
};

/**
 * ModelMetrics – displays model performance comparison cards.
 *
 * Props:
 *   metricsData – full /api/model/metrics response
 */
export default function ModelMetrics({ metricsData }) {
  if (!metricsData) return null;

  const { models = [], best_model } = metricsData;

  // Prepare radar chart data
  const radarData = [
    { metric: 'Accuracy', ...Object.fromEntries(models.map(m => [m.model_name, m.accuracy * 100])) },
    { metric: 'Precision', ...Object.fromEntries(models.map(m => [m.model_name, m.precision * 100])) },
    { metric: 'Recall', ...Object.fromEntries(models.map(m => [m.model_name, m.recall * 100])) },
    { metric: 'F1-Score', ...Object.fromEntries(models.map(m => [m.model_name, m.f1_score * 100])) },
  ];

  return (
    <div>
      {/* Model comparison cards */}
      <div className="metrics-grid">
        {models.map((model) => {
          const isBest = model.model_name === best_model;
          const color = COLORS[model.model_name] || '#22c55e';
          const metrics = [
            { label: 'Accuracy', value: (model.accuracy * 100).toFixed(2) + '%' },
            { label: 'Precision', value: (model.precision * 100).toFixed(2) + '%' },
            { label: 'Recall', value: (model.recall * 100).toFixed(2) + '%' },
            { label: 'F1-Score', value: (model.f1_score * 100).toFixed(2) + '%' },
          ];

          return (
            <div key={model.model_name} className={`model-card ${isBest ? 'best' : ''}`}>
              <div
                style={{
                  width: 40,
                  height: 4,
                  background: color,
                  borderRadius: 2,
                  marginBottom: 16,
                  boxShadow: `0 0 8px ${color}80`,
                }}
              />
              <div className="model-name">{model.model_name}</div>

              {metrics.map(({ label, value }) => (
                <div key={label} className="metric-row">
                  <span className="metric-label">{label}</span>
                  <div>
                    <span className="metric-value">{value}</span>
                    <div className="metric-bar">
                      <div
                        className="metric-bar-fill"
                        style={{
                          width: value,
                          background: color,
                        }}
                      />
                    </div>
                  </div>
                </div>
              ))}

              {/* Confusion Matrix */}
              {model.confusion_matrix && (
                <div style={{ marginTop: 16 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.6px' }}>
                    Confusion Matrix
                  </div>
                  <div className="confusion-matrix">
                    <div className="cm-cell tn">
                      <div className="cm-value" style={{ color: 'var(--color-green)' }}>
                        {model.confusion_matrix.true_negative}
                      </div>
                      <div className="cm-label">True Neg</div>
                    </div>
                    <div className="cm-cell fp">
                      <div className="cm-value" style={{ color: 'var(--color-red)' }}>
                        {model.confusion_matrix.false_positive}
                      </div>
                      <div className="cm-label">False Pos</div>
                    </div>
                    <div className="cm-cell fn">
                      <div className="cm-value" style={{ color: 'var(--color-amber)' }}>
                        {model.confusion_matrix.false_negative}
                      </div>
                      <div className="cm-label">False Neg</div>
                    </div>
                    <div className="cm-cell tp">
                      <div className="cm-value" style={{ color: 'var(--color-green)' }}>
                        {model.confusion_matrix.true_positive}
                      </div>
                      <div className="cm-label">True Pos</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Radar comparison chart */}
      {models.length > 1 && (
        <div className="chart-card" style={{ marginTop: 24 }}>
          <div className="chart-title">Model Comparison Radar</div>
          <ResponsiveContainer width="100%" height={280}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="var(--border-primary)" />
              <PolarAngleAxis
                dataKey="metric"
                tick={{ fill: 'var(--text-muted)', fontSize: 12 }}
              />
              {models.map((model) => (
                <Radar
                  key={model.model_name}
                  name={model.model_name}
                  dataKey={model.model_name}
                  stroke={COLORS[model.model_name] || '#22c55e'}
                  fill={COLORS[model.model_name] || '#22c55e'}
                  fillOpacity={0.15}
                />
              ))}
              <Tooltip
                contentStyle={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-primary)',
                  borderRadius: 8,
                  fontSize: 12,
                }}
                formatter={(val) => val.toFixed(2) + '%'}
              />
            </RadarChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 12, flexWrap: 'wrap' }}>
            {models.map((m) => (
              <div key={m.model_name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                <div style={{ width: 10, height: 10, borderRadius: 2, background: COLORS[m.model_name] }} />
                {m.model_name}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
