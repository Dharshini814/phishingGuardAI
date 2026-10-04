import React, { useState, useEffect } from 'react';
import {
  Activity, ShieldAlert, ShieldCheck, Cpu,
  PieChart as PieIcon, TrendingUp, BarChart2,
} from 'lucide-react';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
} from 'recharts';
import Header from '../components/Header';
import StatCard from '../components/StatCard';
import { getDashboard } from '../api/api';

const COLORS_PIE = ['#ef4444', '#22c55e'];

export default function Dashboard() {
  const [dashData, setDashData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function fetchDashboard() {
    setLoading(true);
    setError('');
    try {
      const data = await getDashboard();
      setDashData(data);
    } catch (err) {
      setError(err.message || 'Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { fetchDashboard(); }, []);

  const pieData = dashData
    ? [
        { name: 'Phishing', value: dashData.phishing_detected || 0 },
        { name: 'Legitimate', value: dashData.legitimate_detected || 0 },
      ].filter((d) => d.value > 0)
    : [];

  const activityData = dashData?.recent_activity?.map((a, i) => ({
    name: `#${i + 1}`,
    risk_score: a.risk_score,
    type: a.prediction,
  })) || [];

  return (
    <div className="page-container animate-fade-in">
      <Header
        title="Dashboard"
        subtitle="Real-time security analytics from your scan session"
        icon={Activity}
        actions={
          <button className="btn btn-ghost" onClick={fetchDashboard} id="refresh-dashboard-btn">
            <Activity size={14} />
            Refresh
          </button>
        }
      />

      {error && (
        <div className="alert alert-error" role="alert">
          <ShieldAlert size={16} />
          {error}
        </div>
      )}

      {loading ? (
        <div className="loading-overlay">
          <div className="spinner" />
          <div className="loading-text">Loading dashboard...</div>
        </div>
      ) : (
        <>
          {/* Stat Cards */}
          <div className="stat-grid">
            <StatCard
              title="Total URLs Analyzed"
              value={dashData?.total_analyzed ?? 0}
              icon={Activity}
              color="blue"
              subtitle="This session"
            />
            <StatCard
              title="Phishing Detected"
              value={dashData?.phishing_detected ?? 0}
              icon={ShieldAlert}
              color="red"
              subtitle="Flagged URLs"
            />
            <StatCard
              title="Legitimate Detected"
              value={dashData?.legitimate_detected ?? 0}
              icon={ShieldCheck}
              color="green"
              subtitle="Clean URLs"
            />
            <StatCard
              title="Model Accuracy"
              value={
                dashData?.model_accuracy
                  ? `${(dashData.model_accuracy * 100).toFixed(1)}%`
                  : 'N/A'
              }
              icon={Cpu}
              color="amber"
              subtitle={dashData?.best_model || 'Best model'}
            />
          </div>

          {/* Charts */}
          <div className="charts-grid">
            {/* Pie Chart */}
            <div className="chart-card">
              <div className="chart-title">
                <PieIcon size={16} />
                Phishing vs Legitimate
              </div>
              {pieData.length === 0 ? (
                <div className="empty-state" style={{ padding: 40 }}>
                  <p className="empty-state-text">No scans yet. Analyze some URLs first.</p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={90}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {pieData.map((_, index) => (
                        <Cell key={index} fill={COLORS_PIE[index % COLORS_PIE.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: 'var(--bg-card)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 8,
                        fontSize: 13,
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              )}
              {pieData.length > 0 && (
                <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 12 }}>
                  {pieData.map((d, i) => (
                    <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      <div style={{ width: 10, height: 10, borderRadius: 2, background: COLORS_PIE[i] }} />
                      {d.name}: {d.value}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Activity Bar Chart */}
            <div className="chart-card">
              <div className="chart-title">
                <BarChart2 size={16} />
                Recent Risk Scores
              </div>
              {activityData.length === 0 ? (
                <div className="empty-state" style={{ padding: 40 }}>
                  <p className="empty-state-text">No recent activity to display.</p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={activityData} barSize={24}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" />
                    <XAxis
                      dataKey="name"
                      tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                      axisLine={{ stroke: 'var(--border-primary)' }}
                    />
                    <YAxis
                      domain={[0, 100]}
                      tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                      axisLine={{ stroke: 'var(--border-primary)' }}
                    />
                    <Tooltip
                      contentStyle={{
                        background: 'var(--bg-card)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                    <Bar
                      dataKey="risk_score"
                      name="Risk Score"
                      fill="#22c55e"
                      radius={[4, 4, 0, 0]}
                      label={false}
                    >
                      {activityData.map((entry, index) => (
                        <Cell
                          key={index}
                          fill={
                            entry.type === 'PHISHING' ? '#ef4444' :
                            entry.risk_score > 30 ? '#f59e0b' : '#22c55e'
                          }
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Info section */}
          {dashData?.total_analyzed === 0 && (
            <div className="alert alert-info" style={{ marginTop: 24 }}>
              <TrendingUp size={16} />
              <span>
                <strong>Get started:</strong> Navigate to the{' '}
                <strong>URL Scanner</strong> page and analyze your first URL to see live dashboard data.
              </span>
            </div>
          )}
        </>
      )}
    </div>
  );
}
