import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: {
    value: string;
    isPositive?: boolean;
  };
  accentColor?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  accentColor = 'var(--accent-cyan)',
}) => {
  return (
    <div className="card p-4 relative overflow-hidden" style={{ padding: '1.25rem' }}>
      <div
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '4px',
          height: '100%',
          backgroundColor: accentColor,
        }}
      />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            {title}
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '0.25rem', color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace' }}>
            {value}
          </div>
          {subtitle && (
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              {subtitle}
            </div>
          )}
          {trend && (
            <div
              style={{
                fontSize: '0.75rem',
                fontWeight: 600,
                marginTop: '0.4rem',
                color: trend.isPositive ? 'var(--status-success)' : 'var(--status-danger)',
              }}
            >
              {trend.value}
            </div>
          )}
        </div>
        <div
          style={{
            padding: '0.6rem',
            borderRadius: 'var(--radius-md)',
            backgroundColor: 'var(--bg-tertiary)',
            color: accentColor,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Icon size={22} />
        </div>
      </div>
    </div>
  );
};
