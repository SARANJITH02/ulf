import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  FlaskConical,
  Radio,
  Cpu,
  Sliders,
  Share2,
  Shield,
  Layers,
  Terminal,
} from 'lucide-react';

interface SidebarProps {
  collapsed?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed = false }) => {
  const navItems = [
    { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/lab', label: 'Unknown Log Lab', icon: FlaskConical, badge: 'Flagship' },
    { to: '/stream', label: 'Live Stream Viewer', icon: Radio, live: true },
    { to: '/parsers', label: 'Parser Manager', icon: Cpu },
    { to: '/rules', label: 'Rules Configuration', icon: Sliders },
    { to: '/export', label: 'SIEM Exporter', icon: Share2 },
  ];

  return (
    <aside
      style={{
        width: collapsed ? '72px' : '260px',
        backgroundColor: 'var(--bg-secondary)',
        borderRight: '1px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        position: 'sticky',
        top: 0,
        transition: 'width 0.2s ease',
        zIndex: 50,
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          padding: '1.25rem 1.25rem',
          borderBottom: '1px solid var(--border-color)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
        }}
      >
        <div
          style={{
            width: '36px',
            height: '36px',
            borderRadius: 'var(--radius-md)',
            background: 'linear-gradient(135deg, #00f0ff 0%, #7c3aed 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#050b14',
            fontWeight: 900,
            boxShadow: '0 0 12px rgba(0, 240, 255, 0.4)',
          }}
        >
          <Shield size={20} color="#050b14" />
        </div>
        {!collapsed && (
          <div>
            <div style={{ fontWeight: 800, fontSize: '1.1rem', letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
              ULPF<span style={{ color: 'var(--accent-cyan)' }}>.io</span>
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Middleware Gateway
            </div>
          </div>
        )}
      </div>

      {/* Navigation Links */}
      <nav style={{ flex: 1, padding: '1rem 0.75rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              justifyContent: collapsed ? 'center' : 'space-between',
              padding: '0.65rem 0.85rem',
              borderRadius: 'var(--radius-md)',
              color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
              backgroundColor: isActive ? 'var(--bg-tertiary)' : 'transparent',
              border: isActive ? '1px solid var(--border-subtle)' : '1px solid transparent',
              textDecoration: 'none',
              fontWeight: isActive ? 700 : 500,
              fontSize: '0.875rem',
              transition: 'all 0.15s ease',
            })}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <item.icon size={18} style={{ color: 'var(--accent-cyan)' }} />
              {!collapsed && <span>{item.label}</span>}
            </div>
            {!collapsed && item.badge && (
              <span
                style={{
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  padding: '0.15rem 0.45rem',
                  borderRadius: 'var(--radius-full)',
                  backgroundColor: 'var(--accent-cyan-subtle)',
                  color: 'var(--accent-cyan)',
                  border: '1px solid rgba(0, 240, 255, 0.3)',
                }}
              >
                {item.badge}
              </span>
            )}
            {!collapsed && item.live && (
              <span className="live-dot" style={{ marginLeft: 'auto' }} />
            )}
          </NavLink>
        ))}
      </nav>

      {/* Status Footer */}
      {!collapsed && (
        <div
          style={{
            padding: '1rem 1.25rem',
            borderTop: '1px solid var(--border-color)',
            backgroundColor: 'var(--bg-primary)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
            <span className="live-dot" />
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Air-Gapped Gateway
            </span>
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
            Syslog UDP/TCP: <strong>Active (1514)</strong><br />
            OCSF Standard: <strong>v1.1.0</strong>
          </div>
        </div>
      )}
    </aside>
  );
};
