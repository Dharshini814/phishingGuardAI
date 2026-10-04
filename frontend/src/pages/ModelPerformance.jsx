import React, { useState, useEffect } from 'react';
import { BarChart3, Database, Layers, AlertCircle } from 'lucide-react';
import Header from '../components/Header';
import ModelMetrics from '../components/ModelMetrics';
import StatCard from '../components/StatCard';
import { getModelMetrics } from '../api/api';

export default function ModelPerformance() {
  const [metricsData, setMetricsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const data = await getModelMetrics();
        setMetricsData(data);
      } catch (err) {
        setError(err.message || 'Failed to load model metrics.');
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  // Feature importance from RF model
  const rfModel = metricsData?.models?.find((m) => m.model_name === 'Random Forest');
  const featureImportances = rfModel?.feature_importances?.slice(0, 15) || [];
  const maxImportance = featureImportances[0]?.importance || 1;

  return (
    <div className="page-container animate-fade-in">
      <Header
        title="Model Performance"
        subtitle="Evaluation metrics from actual training results"
        icon={BarChart3}
      />

      {error && (
        <div className="alert alert-error" role="alert">
          <AlertCircle size={16} />
          {error}
          {error.includes('train') && (
            <span>
              {' '}Run: <code>python model/train_model.py</code> in the backend directory.
            </span>
          )}
        </div>
      )}

      {loading ? (
        <div className="loading-overlay">
          <div className="spinner" />
          <div className="loading-text">Loading model metrics...</div>
        </div>
      ) : metricsData ? (
        <>
          {/* Dataset Info */}
          <div className="stat-grid" style={{ marginBottom: 32 }}>
            <StatCard
              title="Dataset Size"
              value={metricsData.dataset_size?.toLocaleString()}
              icon={Database}
              color="blue"
              subtitle="Total labeled samples"
            />
            <StatCard
              title="Training Samples"
              value={metricsData.train_size?.toLocaleString()}
              icon={Layers}
              color="green"
              subtitle="80% of dataset"
            />
            <StatCard
              title="Testing Samples"
              value={metricsData.test_size?.toLocaleString()}
              icon={Layers}
              color="amber"
              subtitle="20% of dataset"
            />
            <StatCard
              title="Feature Count"
              value={metricsData.feature_count}
              icon={BarChart3}
              color="red"
              subtitle="URL structural features"
            />
          </div>

          <div className="alert alert-info" style={{ marginBottom: 24 }}>
            <AlertCircle size={14} />
            <span>
              <strong>Best model selected: {metricsData.best_model}</strong> — Selected based on
              highest F1-score with priority on phishing recall.
            </span>
          </div>

          {/* Model Cards + Radar */}
          <ModelMetrics metricsData={metricsData} />

          {/* Feature Importance */}
          {featureImportances.length > 0 && (
            <div className="card" style={{ marginTop: 28 }}>
              <div className="card-header">
                <div className="card-title">
                  <BarChart3 size={18} />
                  Random Forest Feature Importance
                </div>
                <span className="card-badge" style={{ background: 'var(--color-green-bg)', color: 'var(--color-green)' }}>
                  Top 15
                </span>
              </div>
              <div className="feature-importance-list">
                {featureImportances.map((fi) => (
                  <div key={fi.feature} className="fi-item">
                    <div className="fi-name">{fi.feature}</div>
                    <div className="fi-bar-track">
                      <div
                        className="fi-bar-fill"
                        style={{ width: `${(fi.importance / maxImportance) * 100}%` }}
                      />
                    </div>
                    <div className="fi-value">
                      {(fi.importance * 100).toFixed(2)}%
                    </div>
                  </div>
                ))}
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 16, fontStyle: 'italic' }}>
                Feature importances are calculated from the trained Random Forest model using
                mean decrease in impurity (Gini importance).
              </p>
            </div>
          )}

          {/* Feature list */}
          <div className="card" style={{ marginTop: 24 }}>
            <div className="card-header">
              <div className="card-title">All Features ({metricsData.feature_count})</div>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {(metricsData.feature_names || []).map((name, i) => (
                <span key={name} className="info-pill">
                  <span style={{ color: 'var(--color-green)', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem' }}>{i}</span>
                  {name}
                </span>
              ))}
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}
