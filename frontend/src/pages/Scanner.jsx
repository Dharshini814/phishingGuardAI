import React, { useState } from 'react';
import { ScanLine, AlertCircle } from 'lucide-react';
import Header from '../components/Header';
import URLScanner from '../components/URLScanner';
import PredictionResult from '../components/PredictionResult';
import RiskIndicator from '../components/RiskIndicator';

export default function Scanner() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  function handleResult(data) {
    setResult(data);
    setError('');
  }

  function handleError(msg) {
    setError(msg);
    setResult(null);
  }

  return (
    <div className="page-container animate-fade-in">
      <Header
        title="URL Scanner"
        subtitle="AI-powered phishing URL analysis using machine learning"
        icon={ScanLine}
      />

      {/* Error alert */}
      {error && (
        <div className="alert alert-error" role="alert" style={{ marginBottom: 20, maxWidth: 800 }}>
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      {/* Loading overlay while analyzing */}
      {isLoading && (
        <div className="scanner-container">
          <div className="card" style={{ textAlign: 'center' }}>
            <div className="loading-overlay">
              <div className="spinner" />
              <div className="loading-text">Analyzing URL...</div>
              <div className="loading-subtext">
                Extracting features and running ML inference. This URL is never fetched.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scanner form */}
      <URLScanner
        onResult={handleResult}
        onError={handleError}
        isLoading={isLoading}
        setIsLoading={setIsLoading}
      />

      {/* Result */}
      {result && !isLoading && (
        <div className="scanner-container" style={{ marginTop: 0 }}>
          <PredictionResult result={result} />
          <div
            style={{
              background: 'var(--bg-card)',
              border: '2px solid',
              borderTop: 'none',
              borderColor: result.prediction === 'PHISHING'
                ? 'var(--color-red)' : 'var(--color-green)',
              borderRadius: '0 0 var(--border-radius-lg) var(--border-radius-lg)',
              overflow: 'hidden',
            }}
          >
            <RiskIndicator
              indicators={result.indicators}
              positiveSignals={result.positive_signals}
              explanation={result.explanation}
            />
          </div>
        </div>
      )}
    </div>
  );
}
