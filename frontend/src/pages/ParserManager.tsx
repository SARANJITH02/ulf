import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { ParserSummary, DlqRecord, DriftAlert, ParserDriftMetrics } from '../api/types';
import { Modal } from '../components/Modal';
import {
  Cpu,
  AlertOctagon,
  RefreshCw,
  Sliders,
  ShieldAlert,
  Activity,
  CheckCircle2,
  TrendingDown,
  TrendingUp,
  AlertTriangle,
  Play,
  RotateCcw,
} from 'lucide-react';

export const ParserManager: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'parsers' | 'drift' | 'dlq'>('parsers');
  const [parsers, setParsers] = useState<ParserSummary[]>([]);
  const [dlqEntries, setDlqEntries] = useState<DlqRecord[]>([]);
  const [driftAlerts, setDriftAlerts] = useState<DriftAlert[]>([]);
  const [parserDriftMap, setParserDriftMap] = useState<Record<string, ParserDriftMetrics>>({});
  const [loading, setLoading] = useState(false);

  // DLQ Detail Modal
  const [selectedDlq, setSelectedDlq] = useState<DlqRecord | null>(null);
  const [dlqModalOpen, setDlqModalOpen] = useState(false);
  const [retrying, setRetrying] = useState(false);

  // Drift Detail Modal
  const [selectedDriftParser, setSelectedDriftParser] = useState<ParserDriftMetrics | null>(null);
  const [scanningDrift, setScanningDrift] = useState(false);

  const currentUser = ApiClient.getCurrentUser();
  const isAdmin = currentUser?.role === 'ADMIN';

  const fetchParsers = async () => {
    try {
      const data = await ApiClient.listParsers();
      setParsers(data);
      // Fetch drift metrics for each parser
      for (const p of data) {
        try {
          const metrics = await ApiClient.getParserDrift(p.name);
          setParserDriftMap((prev) => ({ ...prev, [p.name]: metrics }));
        } catch (ignored) {}
      }
    } catch (e) {
      console.error(e);
    }
  };

  const fetchDlq = async () => {
    try {
      const data = await ApiClient.listDlq();
      setDlqEntries(data.content || []);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchDriftAlerts = async () => {
    try {
      const data = await ApiClient.listDriftAlerts();
      setDriftAlerts(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchParsers();
    fetchDlq();
    fetchDriftAlerts();
  }, []);

  const handleToggleParser = async (name: string, currentActive: boolean) => {
    try {
      await ApiClient.toggleParser(name, !currentActive);
      setParsers((prev) =>
        prev.map((p) => (p.name === name ? { ...p, active: !currentActive } : p))
      );
    } catch (e: any) {
      alert('Toggle error: ' + e.message);
    }
  };

  const handleTriggerDriftScan = async () => {
    try {
      setScanningDrift(true);
      await ApiClient.triggerDriftCheck();
      await fetchParsers();
      await fetchDriftAlerts();
    } catch (e: any) {
      alert('Drift scan error: ' + e.message);
    } finally {
      setScanningDrift(false);
    }
  };

  const handleAcknowledgeAlert = async (id: number) => {
    try {
      await ApiClient.acknowledgeDriftAlert(id);
      await fetchDriftAlerts();
      await fetchParsers();
    } catch (e: any) {
      alert('Error acknowledging alert: ' + e.message);
    }
  };

  const handleRetryDlq = async (id: number) => {
    setRetrying(true);
    try {
      const res = await ApiClient.retryDlq(id);
      alert('Retry executed! Result: ' + (res.pipelineResult?.success ? 'SUCCESS' : 'FAILED - ' + res.pipelineResult?.errorMessage));
      fetchDlq();
      setDlqModalOpen(false);
    } catch (e: any) {
      alert('Retry error: ' + e.message);
    } finally {
      setRetrying(false);
    }
  };

  const handleResolveDlq = async (id: number, status: string) => {
    try {
      await ApiClient.resolveDlq(id, status);
      fetchDlq();
      setDlqModalOpen(false);
    } catch (e: any) {
      alert('Error updating DLQ status: ' + e.message);
    }
  };

  // Sparkline generator
  const renderSparkline = (points: number[]) => {
    if (!points || points.length < 2) return <span style={{ color: 'var(--text-muted)' }}>No data</span>;
    const min = Math.min(...points, 0.5);
    const max = Math.max(...points, 1.0);
    const range = max - min || 1;
    const width = 120;
    const height = 28;

    const pathD = points
      .map((val, idx) => {
        const x = (idx / (points.length - 1)) * width;
        const y = height - ((val - min) / range) * (height - 6) - 3;
        return `${idx === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
      })
      .join(' ');

    const lastVal = points[points.length - 1];
    const firstVal = points[0];
    const isDegrading = lastVal < firstVal;

    return (
      <svg width={width} height={height} style={{ overflow: 'visible', verticalAlign: 'middle' }}>
        <path d={pathD} fill="none" stroke={isDegrading ? 'var(--status-danger)' : 'var(--status-success)'} strokeWidth="2" strokeLinecap="round" />
      </svg>
    );
  };

  const openAlertsCount = driftAlerts.filter((a) => a.status === 'OPEN').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              padding: '0.5rem',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--accent-cyan-subtle)',
              color: 'var(--accent-cyan)',
              display: 'flex',
            }}
          >
            <Cpu size={24} />
          </div>
          <div>
            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em', margin: 0 }}>
              Parser Hot-Registry & Quality Drift Monitor
            </h1>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', margin: '0.25rem 0 0' }}>
              Zero-downtime parser hot-loading, real-time quality degradation tracking, and Dead-Letter Queue quarantine management
            </p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div style={{ display: 'flex', backgroundColor: 'var(--bg-secondary)', padding: '0.25rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
          <button
            onClick={() => setActiveTab('parsers')}
            className={`btn ${activeTab === 'parsers' ? 'btn-primary' : 'btn-ghost'}`}
            style={{ fontSize: '0.8125rem', padding: '0.45rem 0.95rem' }}
          >
            <Cpu size={14} />
            <span>Active Parsers ({parsers.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('drift')}
            className={`btn ${activeTab === 'drift' ? 'btn-primary' : 'btn-ghost'}`}
            style={{ fontSize: '0.8125rem', padding: '0.45rem 0.95rem' }}
          >
            <ShieldAlert size={14} />
            <span>Drift Alerts ({openAlertsCount})</span>
          </button>
          <button
            onClick={() => setActiveTab('dlq')}
            className={`btn ${activeTab === 'dlq' ? 'btn-primary' : 'btn-ghost'}`}
            style={{ fontSize: '0.8125rem', padding: '0.45rem 0.95rem' }}
          >
            <AlertOctagon size={14} />
            <span>DLQ Inspector ({dlqEntries.length})</span>
          </button>
        </div>
      </div>

      {/* TAB 1: ACTIVE PARSERS */}
      {activeTab === 'parsers' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Registered Parser Engine Plugins & Live Drift Status
            </span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              {isAdmin && (
                <button
                  onClick={handleTriggerDriftScan}
                  className="btn btn-secondary"
                  disabled={scanningDrift}
                  style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                >
                  <Activity size={14} className={scanningDrift ? 'spin' : ''} />
                  {scanningDrift ? 'Scanning Drift...' : 'Scan Quality Drift'}
                </button>
              )}
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem', textAlign: 'left' }}>
              <thead>
                <tr style={{ backgroundColor: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Parser Identifier</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Display Name</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Format</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Version</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Quality & Drift Health</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Confidence Trend</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Status</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {parsers.map((p) => {
                  const drift = parserDriftMap[p.name];
                  const health = drift?.healthStatus || 'HEALTHY';
                  const dropPct = drift ? (drift.confidenceDrop * 100).toFixed(1) : '0.0';

                  return (
                    <tr key={p.name} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                        {p.name}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {p.displayName}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>{p.formatType}</span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace' }}>
                        v{p.version}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        {health === 'DRIFT_ALERT' ? (
                          <span className="badge badge-danger" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontWeight: 700 }}>
                            <AlertTriangle size={12} /> DRIFT BREACH (-{dropPct}%)
                          </span>
                        ) : health === 'WARNING' ? (
                          <span className="badge badge-warning" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                            <TrendingDown size={12} /> DEGRADING (-{dropPct}%)
                          </span>
                        ) : (
                          <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                            <CheckCircle2 size={12} /> OPTIMAL ({(drift?.currentConfidence ? drift.currentConfidence * 100 : 95).toFixed(0)}%)
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        {drift?.confidenceHistory ? renderSparkline(drift.confidenceHistory) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.35rem',
                            color: p.active ? 'var(--status-success)' : 'var(--status-danger)',
                            fontWeight: 600,
                          }}
                        >
                          <span
                            style={{
                              width: '8px',
                              height: '8px',
                              borderRadius: '50%',
                              backgroundColor: p.active ? 'var(--status-success)' : 'var(--status-danger)',
                            }}
                          />
                          {p.active ? 'LIVE' : 'DISABLED'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.4rem' }}>
                          <button
                            onClick={() => drift && setSelectedDriftParser(drift)}
                            className="btn btn-secondary"
                            style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem' }}
                          >
                            Metrics
                          </button>
                          {isAdmin && (
                            <button
                              onClick={() => handleToggleParser(p.name, p.active)}
                              className={`btn ${p.active ? 'btn-ghost' : 'btn-primary'}`}
                              style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem' }}
                            >
                              {p.active ? 'Disable' : 'Enable'}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: DRIFT ALERTS */}
      {activeTab === 'drift' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Parser Quality Degradation Alerts
            </span>
            <button
              onClick={handleTriggerDriftScan}
              className="btn btn-primary"
              disabled={scanningDrift}
              style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <RefreshCw size={14} className={scanningDrift ? 'spin' : ''} />
              Scan Now
            </button>
          </div>

          {driftAlerts.length === 0 ? (
            <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
              <CheckCircle2 size={36} style={{ margin: '0 auto 1rem', color: 'var(--status-success)' }} />
              <div style={{ fontWeight: 600 }}>All Parsers Operating at High Confidence</div>
              <p style={{ fontSize: '0.875rem', marginTop: '0.25rem' }}>
                No active quality drift breaches detected across the rolling event window.
              </p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem', textAlign: 'left' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Detected At</th>
                    <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Parser Identifier</th>
                    <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Baseline vs Current</th>
                    <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Confidence Drop</th>
                    <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Success Rate</th>
                    <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Status</th>
                    <th style={{ padding: '0.75rem 1rem', fontWeight: 700, textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {driftAlerts.map((a) => (
                    <tr key={a.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                        {new Date(a.detectedAt).toISOString().replace('T', ' ').substring(0, 19)}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                        {a.parserName}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        {(a.baselineConfidence * 100).toFixed(0)}% → {(a.currentConfidence * 100).toFixed(0)}%
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--status-danger)', fontWeight: 700 }}>
                        -{(a.confidenceDrop * 100).toFixed(1)}%
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        {(a.successRate * 100).toFixed(1)}% ({a.totalEvents} events)
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className={`badge ${a.status === 'OPEN' ? 'badge-danger' : 'badge-neutral'}`}>
                          {a.status}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        {isAdmin && a.status === 'OPEN' && (
                          <button
                            onClick={() => handleAcknowledgeAlert(a.id)}
                            className="btn btn-secondary"
                            style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem' }}
                          >
                            Acknowledge
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: DLQ INSPECTOR */}
      {activeTab === 'dlq' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Dead-Letter Queue (DLQ) Diagnostic Records
            </span>
            <button onClick={fetchDlq} className="btn btn-ghost" style={{ fontSize: '0.75rem' }}>
              <RefreshCw size={14} />
              <span>Refresh DLQ</span>
            </button>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem', textAlign: 'left' }}>
              <thead>
                <tr style={{ backgroundColor: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Timestamp</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Raw ID</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Failure Code</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Failure Reason</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Status</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {dlqEntries.map((d) => (
                  <tr key={d.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                      {new Date(d.createdAt).toISOString().replace('T', ' ').substring(0, 19)}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace' }}>
                      {d.rawEventId}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span className="badge badge-danger">{d.failureCode}</span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                      {d.failureReason}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span className="badge badge-warning">{d.status}</span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                      <button
                        onClick={() => {
                          setSelectedDlq(d);
                          setDlqModalOpen(true);
                        }}
                        className="btn btn-secondary"
                        style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem' }}
                      >
                        Inspect & Retry
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Parser Drift Metrics Modal */}
      {selectedDriftParser && (
        <Modal
          isOpen={true}
          onClose={() => setSelectedDriftParser(null)}
          title={`Parser Drift Telemetry — ${selectedDriftParser.parserName}`}
        >
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', marginBottom: '1.25rem' }}>
            <div style={{ backgroundColor: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: 'var(--radius-md)' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Baseline Confidence</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>
                {(selectedDriftParser.baselineConfidence * 100).toFixed(1)}%
              </div>
            </div>
            <div style={{ backgroundColor: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: 'var(--radius-md)' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Rolling Confidence</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 800, color: selectedDriftParser.confidenceDrop >= 0.15 ? 'var(--status-danger)' : 'var(--status-success)' }}>
                {(selectedDriftParser.currentConfidence * 100).toFixed(1)}%
              </div>
            </div>
            <div style={{ backgroundColor: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: 'var(--radius-md)' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Success Rate (24h)</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                {(selectedDriftParser.successRate * 100).toFixed(1)}%
              </div>
            </div>
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <div style={{ fontWeight: 700, fontSize: '0.85rem', marginBottom: '0.5rem', color: 'var(--text-primary)' }}>
              Confidence Trend History (Chronological Rolling Window)
            </div>
            <div style={{ backgroundColor: 'var(--bg-tertiary)', padding: '1rem', borderRadius: 'var(--radius-md)', display: 'flex', justifyContent: 'center' }}>
              {selectedDriftParser.confidenceHistory && renderSparkline(selectedDriftParser.confidenceHistory)}
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button onClick={() => setSelectedDriftParser(null)} className="btn btn-secondary">
              Close
            </button>
          </div>
        </Modal>
      )}

      {/* DLQ Modal */}
      {dlqModalOpen && selectedDlq && (
        <Modal
          isOpen={true}
          onClose={() => setDlqModalOpen(false)}
          title={`DLQ Record #${selectedDlq.id} — ${selectedDlq.failureCode}`}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                RAW UNPARSEABLE LOG PAYLOAD
              </div>
              <pre style={{ backgroundColor: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: 'var(--radius-md)', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem', whiteSpace: 'pre-wrap', border: '1px solid var(--border-color)' }}>
                {selectedDlq.rawMessage}
              </pre>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <button onClick={() => handleResolveDlq(selectedDlq.id, 'DISCARDED')} className="btn btn-ghost">
                Discard Record
              </button>
              <button onClick={() => handleRetryDlq(selectedDlq.id)} className="btn btn-primary" disabled={retrying}>
                <RotateCcw size={14} />
                {retrying ? 'Retrying Pipeline...' : 'Re-Ingest Through Pipeline'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
