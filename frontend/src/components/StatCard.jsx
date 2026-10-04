import React from 'react';

/**
 * StatCard – displays a single metric with icon, value and label.
 *
 * Props:
 *   title     – Label text
 *   value     – Main numeric/text value
 *   icon      – Lucide icon component
 *   color     – 'green' | 'red' | 'blue' | 'amber'
 *   subtitle  – Optional small text below value
 */
export default function StatCard({ title, value, icon: Icon, color = 'blue', subtitle }) {
  return (
    <div className={`stat-card ${color}`}>
      <div className="stat-card-header">
        <div className={`stat-card-icon ${color}`}>
          {Icon && <Icon size={22} />}
        </div>
      </div>
      <div className="stat-card-value">
        {value !== null && value !== undefined ? value : '—'}
      </div>
      <div className="stat-card-label">{title}</div>
      {subtitle && (
        <div className="stat-card-trend" style={{ color: 'var(--text-muted)' }}>
          {subtitle}
        </div>
      )}
    </div>
  );
}
