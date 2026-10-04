import React, { useState, useEffect } from 'react';
import { History as HistoryIcon, Trash2, RefreshCw, AlertCircle } from 'lucide-react';
import Header from '../components/Header';
import HistoryTable from '../components/HistoryTable';
import { getHistory, clearHistory } from '../api/api';

export default function History() {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [clearing, setClearing] = useState(false);

  async function fetchHistory() {
    setLoading(true);
    setError('');
    try {
      const data = await getHistory();
      setRecords(data.history || []);
    } catch (err) {
      setError(err.message || 'Failed to load history.');
    } finally {
      setLoading(false);
    }
  }

  async function handleClear() {
    if (!window.confirm('Clear all scan history? This cannot be undone.')) return;
    setClearing(true);
    try {
      await clearHistory();
      setRecords([]);
    } catch (err) {
      setError(err.message || 'Failed to clear history.');
    } finally {
      setClearing(false);
    }
  }

  useEffect(() => { fetchHistory(); }, []);

  return (
    <div className="page-container animate-fade-in">
      <Header
        title="Analysis History"
        subtitle={`${records.length} scan${records.length !== 1 ? 's' : ''} in this session`}
        icon={HistoryIcon}
        actions={
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              className="btn btn-ghost"
              onClick={fetchHistory}
              disabled={loading}
              id="refresh-history-btn"
            >
              <RefreshCw size={14} />
              Refresh
            </button>
            {records.length > 0 && (
              <button
                className="btn btn-danger"
                onClick={handleClear}
                disabled={clearing}
                id="clear-history-btn"
              >
                <Trash2 size={14} />
                {clearing ? 'Clearing...' : 'Clear History'}
              </button>
            )}
          </div>
        }
      />

      {error && (
        <div className="alert alert-error" role="alert">
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      <div className="alert alert-warning" style={{ marginBottom: 20 }}>
        <AlertCircle size={14} />
        <span>
          History is stored in memory only and will be lost when the server restarts.
          No sensitive data (passwords, tokens, or cookies) is stored.
        </span>
      </div>

      {loading ? (
        <div className="loading-overlay">
          <div className="spinner" />
          <div className="loading-text">Loading history...</div>
        </div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <HistoryTable records={records} />
        </div>
      )}
    </div>
  );
}
