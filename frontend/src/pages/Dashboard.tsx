import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { wsService } from '../api/websocket';
import { MetricsSnapshot, NormalizedEventRecord } from '../api/types';
import { StatCard } from '../components/StatCard';
import { ConfidenceBadge } from '../components/ConfidenceBadge';
import {
  Activity,
  Zap,
  CheckCircle2,
  AlertOctagon,
  Clock,
  Layers,
  ArrowUpRight,
  Send,
  ShieldAlert,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [metrics, setMetrics] = useState<MetricsSnapshot>({
    timestamp: new Date().toISOString(),
    eventsPerSecond: 0,
    totalEvents: 0,
    successfulEvents: 0,
    dlqEvents: 0,
    successRatePercentage: 100,
    avgLatencyMs: 0,
    p50LatencyMs: 0,
    p95LatencyMs: 0,
    p99LatencyMs: 0,
    formatDistribution: { SYSLOG: 0, CEF: 0, LEEF: 0, JSON: 0, CSV: 0, CUSTOM: 0, UNKNOWN: 0 },
    confidenceDistribution: { HIGH: 0, MEDIUM: 0, LOW: 0 },
  });

  const [recentEvents, setRecentEvents] = useState<NormalizedEventRecord[]>([]);
  const [injecting, setInjecting] = useState(false);

  useEffect(() => {
    // Initial fetch
    ApiClient.getMetrics().then(setMetrics).catch(() => {});
    ApiClient.getRecentEvents().then(setRecentEvents).catch(() => {});

    // WebSocket live stream
    const unsubMetrics = wsService.onMetrics((data) => {
      setMetrics(data);
    });

    const unsubEvents = wsService.onEvent(() => {
      ApiClient.getRecentEvents().then(setRecentEvents).catch(() => {});
    });

    // Fallback refresh interval
    const interval = setInterval(() => {
      ApiClient.getMetrics().then(setMetrics).catch(() => {});
    }, 3000);

    return () => {
      unsubMetrics();
      unsubEvents();
      clearInterval(interval);
    };
  }, []);

  const handleInjectSample = async () => {
    setInjecting(true);
    const samples = [
      '<134>Aug 30 10:32:21 cisco-asa %ASA-4-106023: Deny tcp src inside:192.168.1.5/52100 dst outside:10.10.10.20/443 by access-group "access-group-dmz-01"',
      'CEF:0|Suricata|Network-IDS|6.0.4|2001219|ET SCAN Potential SSH Scan|3|src=192.168.1.150 dst=10.10.10.20 spt=49152 dpt=22 proto=TCP act=blocked msg=ET SCAN',
      '1,2026/08/30 10:32:21,001801000001,TRAFFIC,drop,1,2026/08/30 10:32:21,192.168.1.105,10.10.10.35,0.0.0.0,0.0.0.0,rule-block-dmz,jdoe,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/08/30 10:32:21,12345,1,54321,80,0,0,0x0,tcp,deny,1200,600,600,10,2026/08/30 10:32:21,0,any,0,123456789,0x0,192.168.0.0-192.168.255.255,10.0.0.0-10.255.255.255,0,5,5,0,0,,0,0,0,0,',
      '{"eventTime":"2026-08-30T10:32:21Z","eventSource":"iam.amazonaws.com","eventName":"CreateUser","sourceIPAddress":"192.168.1.100","userIdentity":{"userName":"secops_admin"}}',
    ];
    try {
      await ApiClient.ingestBulk(samples, 'DEMO_INJECTOR');
      const updatedMetrics = await ApiClient.getMetrics();
      setMetrics(updatedMetrics);
      const updatedEvents = await ApiClient.getRecentEvents();
      setRecentEvents(updatedEvents);
    } catch (e) {
      console.error(e);
    } finally {
      setInjecting(false);
    }
  };

  const totalFormatCount = Object.values(metrics.formatDistribution || {}).reduce((a, b) => a + b, 0);
  const totalConfidenceCount = Object.values(metrics.confidenceDistribution || {}).reduce((a, b) => a + b, 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Header & Actions */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
            Operations & Normalization Dashboard
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
            Real-time perimeter telemetry, format ingestion distribution, and pipeline health
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            onClick={handleInjectSample}
            disabled={injecting}
            className="btn btn-secondary"
            style={{ fontSize: '0.8125rem' }}
          >
            <Send size={14} color="var(--accent-cyan)" />
            <span>{injecting ? 'Injecting...' : 'Inject Sample Burst'}</span>
          </button>
          <button
            onClick={() => navigate('/lab')}
            className="btn btn-primary"
            style={{ fontSize: '0.8125rem' }}
          >
            <span>Unknown Log Lab</span>
            <ArrowUpRight size={16} />
          </button>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
        <StatCard
          title="Throughput"
          value={`${metrics.eventsPerSecond} EPS`}
          subtitle="Sliding 5s window"
          icon={Activity}
          accentColor="var(--accent-cyan)"
        />
        <StatCard
          title="Avg Latency"
          value={`${metrics.avgLatencyMs} ms`}
          subtitle={`p50: ${metrics.p50LatencyMs}ms | p99: ${metrics.p99LatencyMs}ms`}
          icon={Zap}
          accentColor="var(--accent-purple)"
        />
        <StatCard
          title="Success Rate"
          value={`${metrics.successRatePercentage}%`}
          subtitle={`${metrics.successfulEvents} / ${metrics.totalEvents} normalized`}
          icon={CheckCircle2}
          accentColor="var(--status-success)"
        />
        <StatCard
          title="Dead-Letter Queue"
          value={metrics.dlqEvents}
          subtitle="Events requiring inspection"
          icon={AlertOctagon}
          accentColor={metrics.dlqEvents > 0 ? 'var(--status-danger)' : 'var(--text-muted)'}
        />
      </div>

      {/* Charts & Breakdown Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '1.25rem' }}>
        {/* Format Distribution Card */}
        <div className="card p-4" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Layers size={18} color="var(--accent-cyan)" />
              Detected Log Formats
            </h3>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)' }}>
              {totalFormatCount} Total
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            {Object.entries(metrics.formatDistribution || {}).map(([fmt, count]) => {
              const pct = totalFormatCount > 0 ? Math.round((count / totalFormatCount) * 100) : 0;
              return (
                <div key={fmt}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{fmt}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>
                      {count} ({pct}%)
                    </span>
                  </div>
                  <div
                    style={{
                      height: '6px',
                      backgroundColor: 'var(--bg-tertiary)',
                      borderRadius: '3px',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${pct}%`,
                        height: '100%',
                        backgroundColor:
                          fmt === 'SYSLOG'
                            ? '#00f0ff'
                            : fmt === 'CEF'
                            ? '#2563eb'
                            : fmt === 'JSON'
                            ? '#7c3aed'
                            : fmt === 'CSV'
                            ? '#ffb300'
                            : '#00e676',
                        borderRadius: '3px',
                        transition: 'width 0.3s ease',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Confidence Tier Matrix */}
        <div className="card p-4" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldAlert size={18} color="var(--status-success)" />
              Mapping Confidence Distribution
            </h3>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)' }}>
              {totalConfidenceCount} Scored
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem', marginTop: '0.5rem' }}>
            <div
              style={{
                backgroundColor: 'var(--status-success-bg)',
                border: '1px solid rgba(0, 230, 118, 0.3)',
                borderRadius: 'var(--radius-md)',
                padding: '1rem',
                textAlign: 'center',
              }}
            >
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--status-success)' }}>
                HIGH (≥90%)
              </div>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--status-success)', margin: '0.25rem 0' }}>
                {metrics.confidenceDistribution?.HIGH || 0}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Auto-Recommended</div>
            </div>

            <div
              style={{
                backgroundColor: 'var(--status-warning-bg)',
                border: '1px solid rgba(255, 179, 0, 0.3)',
                borderRadius: 'var(--radius-md)',
                padding: '1rem',
                textAlign: 'center',
              }}
            >
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--status-warning)' }}>
                MED (70-89%)
              </div>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--status-warning)', margin: '0.25rem 0' }}>
                {metrics.confidenceDistribution?.MEDIUM || 0}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Review Queue</div>
            </div>

            <div
              style={{
                backgroundColor: 'var(--status-danger-bg)',
                border: '1px solid rgba(255, 61, 113, 0.3)',
                borderRadius: 'var(--radius-md)',
                padding: '1rem',
                textAlign: 'center',
              }}
            >
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--status-danger)' }}>
                LOW (&lt;70%)
              </div>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--status-danger)', margin: '0.25rem 0' }}>
                {metrics.confidenceDistribution?.LOW || 0}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>DLQ Escalated</div>
            </div>
          </div>

          <div style={{ marginTop: '1.25rem', fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
            <p>
              • <strong>Deterministic Gate:</strong> High-confidence models recommend mapping but always require human sign-off.<br />
              • <strong>Air-Gapped Operation:</strong> Zero cloud lookups; local RFC1918 & IANA ports applied on-the-fly.
            </p>
          </div>
        </div>
      </div>

      {/* Live Stream Table Snapshot */}
      <div className="card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span className="live-dot" />
              Live Processed Stream (Latest Events)
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Normalized canonical events in OCSF schema with cryptographic digests
            </p>
          </div>
          <button
            onClick={() => navigate('/stream')}
            className="btn btn-ghost"
            style={{ fontSize: '0.8125rem' }}
          >
            View Full Stream & Audit
            <ArrowUpRight size={14} />
          </button>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.6rem 0.75rem', fontWeight: 600 }}>Event ID</th>
                <th style={{ padding: '0.6rem 0.75rem', fontWeight: 600 }}>Format</th>
                <th style={{ padding: '0.6rem 0.75rem', fontWeight: 600 }}>Source IP</th>
                <th style={{ padding: '0.6rem 0.75rem', fontWeight: 600 }}>Destination IP</th>
                <th style={{ padding: '0.6rem 0.75rem', fontWeight: 600 }}>Action</th>
                <th style={{ padding: '0.6rem 0.75rem', fontWeight: 600 }}>Confidence</th>
                <th style={{ padding: '0.6rem 0.75rem', fontWeight: 600 }}>Parser</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                    No events received yet. Click "Inject Sample Burst" or send Syslog to port 1514.
                  </td>
                </tr>
              ) : (
                recentEvents.slice(0, 8).map((evt) => (
                  <tr
                    key={evt.eventId}
                    style={{ borderBottom: '1px solid var(--border-color)', transition: 'background-color 0.15s' }}
                    className="card-interactive"
                  >
                    <td style={{ padding: '0.6rem 0.75rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)' }}>
                      {evt.eventId.substring(0, 18)}...
                    </td>
                    <td style={{ padding: '0.6rem 0.75rem' }}>
                      <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>{evt.format}</span>
                    </td>
                    <td style={{ padding: '0.6rem 0.75rem', fontFamily: 'JetBrains Mono, monospace' }}>
                      {evt.sourceIp || '—'}
                    </td>
                    <td style={{ padding: '0.6rem 0.75rem', fontFamily: 'JetBrains Mono, monospace' }}>
                      {evt.destinationIp || '—'}{evt.destinationPort ? `:${evt.destinationPort}` : ''}
                    </td>
                    <td style={{ padding: '0.6rem 0.75rem' }}>
                      <span
                        className={`badge ${
                          evt.action === 'blocked' ? 'badge-danger' : 'badge-success'
                        }`}
                        style={{ fontSize: '0.65rem' }}
                      >
                        {evt.action || 'allowed'}
                      </span>
                    </td>
                    <td style={{ padding: '0.6rem 0.75rem' }}>
                      <ConfidenceBadge confidence={evt.averageConfidence} size="sm" />
                    </td>
                    <td style={{ padding: '0.6rem 0.75rem', color: 'var(--text-secondary)' }}>
                      {evt.parserName}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
