import React from 'react';
import { Menu, Shield } from 'lucide-react';

export default function Header({ title, subtitle, icon: Icon, actions, onMenuToggle }) {
  return (
    <>
      {/* Mobile menu toggle */}
      <button
        className="mobile-menu-btn"
        onClick={onMenuToggle}
        aria-label="Toggle sidebar"
        id="mobile-menu-btn"
      >
        <Menu size={20} />
      </button>

      <div className="page-header">
        <div className="page-header-content">
          <div>
            <h1 className="page-title">
              {Icon && (
                <div className="page-title-icon">
                  <Icon size={22} />
                </div>
              )}
              {title}
            </h1>
            {subtitle && (
              <p className="page-subtitle">{subtitle}</p>
            )}
          </div>
          {actions && (
            <div className="page-header-actions">{actions}</div>
          )}
        </div>
      </div>
    </>
  );
}
