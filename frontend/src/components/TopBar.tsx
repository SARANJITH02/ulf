import React, { useEffect, useState } from 'react';
import { useTheme } from '../theme/ThemeContext';
import { ApiClient } from '../api/client';
import { Sun, Moon, LogOut, Shield, Activity, Lock } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const TopBar: React.FC = () => {
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const [timeUtc, setTimeUtc] = useState('');
  const user = ApiClient.getCurrentUser();

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeUtc(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    ApiClient.logout();
    navigate('/login');
  };

  return (
    <header
      style={{
        height: '64px',
        backgroundColor: 'var(--bg-secondary)',
        borderBottom: '1px solid var(--border-color)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 1.5rem',
        position: 'sticky',
        top: 0,
        zIndex: 40,
      }}
    >
      {/* Left Indicators */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span className="live-dot" />
          <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            PIPELINE ACTIVE
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span className="badge badge-info" style={{ fontSize: '0.7rem' }}>
            <Activity size={12} /> UDP/TCP :1514
          </span>
          <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>
            <Lock size={12} /> AIR-GAPPED
          </span>
        </div>
      </div>

      {/* Right Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {/* UTC Clock */}
        <div
          style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
            backgroundColor: 'var(--bg-tertiary)',
            padding: '0.35rem 0.75rem',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border-color)',
          }}
        >
          {timeUtc}
        </div>

        {/* Theme Toggle Button */}
        <button
          onClick={toggleTheme}
          className="btn btn-secondary"
          style={{ padding: '0.45rem', borderRadius: 'var(--radius-md)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
          title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} mode`}
        >
          {theme === 'dark' ? <Sun size={18} color="#ffb300" /> : <Moon size={18} color="#2563eb" />}
        </button>

        {/* User Info & Logout */}
        {user ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                {user.fullName || user.username}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                {user.role}
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="btn btn-ghost"
              style={{ padding: '0.45rem', borderRadius: 'var(--radius-md)', color: 'var(--status-danger)' }}
              title="Logout"
            >
              <LogOut size={18} />
            </button>
          </div>
        ) : (
          <button onClick={() => navigate('/login')} className="btn btn-primary" style={{ fontSize: '0.8125rem' }}>
            Login
          </button>
        )}
      </div>
    </header>
  );
};
