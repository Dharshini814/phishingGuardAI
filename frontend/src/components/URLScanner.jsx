import React, { useState } from 'react';
import { ScanLine, AlertCircle, Lock, Globe } from 'lucide-react';
import { predictUrl } from '../api/api';

/**
 * URLScanner – input form for submitting a URL for phishing analysis.
 *
 * Props:
 *   onResult  – callback(result) when prediction succeeds
 *   onError   – callback(errorMessage) when prediction fails
 *   isLoading – bool, controls the loading state
 *   setIsLoading – setter for isLoading
 */
export default function URLScanner({ onResult, onError, isLoading, setIsLoading }) {
  const [url, setUrl] = useState('');
  const [inputError, setInputError] = useState('');

  function validateInput(value) {
    if (!value.trim()) return 'Please enter a URL.';
    if (!value.trim().match(/^https?:\/\//i))
      return 'URL must start with http:// or https://';
    if (value.trim().length > 2048)
      return 'URL is too long (maximum 2048 characters).';
    return '';
  }

  async function handleAnalyze(e) {
    e.preventDefault();
    const trimmed = url.trim();
    const err = validateInput(trimmed);
    if (err) {
      setInputError(err);
      return;
    }
    setInputError('');
    setIsLoading(true);
    onResult(null); // clear previous result

    try {
      const result = await predictUrl(trimmed);
      onResult(result);
    } catch (error) {
      onError(error.message || 'Analysis failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="scanner-container">
      <div className="scanner-card">
        <h2 className="scanner-title">Analyze a Website URL</h2>
        <p className="scanner-subtitle">
          Enter a URL to analyze its structural characteristics for phishing indicators.
          The URL is never visited or fetched — only the URL string is analyzed.
        </p>

        <form onSubmit={handleAnalyze} noValidate>
          <div className="url-input-wrapper">
            <input
              id="url-input"
              type="url"
              className={`url-input ${inputError ? 'error' : ''}`}
              placeholder="https://example.com/login"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (inputError) setInputError('');
              }}
              disabled={isLoading}
              autoComplete="off"
              spellCheck="false"
              aria-label="URL to analyze"
            />
            <button
              id="analyze-btn"
              type="submit"
              className="scan-btn"
              disabled={isLoading || !url.trim()}
            >
              {isLoading ? (
                <>
                  <span
                    style={{
                      width: 14,
                      height: 14,
                      border: '2px solid rgba(255,255,255,0.4)',
                      borderTopColor: '#fff',
                      borderRadius: '50%',
                      display: 'inline-block',
                      animation: 'spin 0.8s linear infinite',
                    }}
                  />
                  Analyzing...
                </>
              ) : (
                <>
                  <ScanLine size={15} />
                  Analyze URL
                </>
              )}
            </button>
          </div>

          {inputError && (
            <div className="input-error" role="alert">
              <AlertCircle size={14} />
              {inputError}
            </div>
          )}
        </form>

        <div className="scan-info" style={{ marginTop: 20 }}>
          <Lock size={13} />
          <span>
            <strong style={{ color: 'var(--text-secondary)' }}>Security notice:</strong>{' '}
            This tool performs URL string analysis only. The submitted URL is never visited,
            crawled, or executed.
          </span>
        </div>

        {/* Example URLs */}
        <div style={{ marginTop: 20 }}>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 8 }}>
            Try an example:
          </p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {[
              'https://www.google.com',
              'https://www.github.com/tensorflow',
              'http://paypal-secure-verify.xyz/signin?token=abc',
              'http://192.168.1.1/banking/login.php',
            ].map((example) => (
              <button
                key={example}
                type="button"
                className="btn btn-ghost"
                style={{ fontSize: '0.72rem', padding: '4px 10px', fontFamily: 'JetBrains Mono, monospace' }}
                onClick={() => { setUrl(example); setInputError(''); }}
              >
                <Globe size={11} />
                {example.length > 35 ? example.slice(0, 35) + '…' : example}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
