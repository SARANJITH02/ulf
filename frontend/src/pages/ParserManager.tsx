import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { ParserSummary, DlqRecord } from '../api/types';
import { ConfidenceBadge } from '../components/ConfidenceBadge';
import { Modal } from '../components/Modal';
import {
  Cpu,
  AlertOctagon,
  CheckCircle2,
  RefreshCw,
  Play,
  RotateCcw,
  Sliders,
  Shield,
  Layers,
} from 'lucide-react';

export const ParserManager: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'parsers' | 'dlq'>('parsers');
  const [parsers, setParsers] = useState<ParserSummary[]>([]);
  const [dlqEntries, setDlqEntries] = useState<DlqRecord[]>([]);
  const [loading, setLoading] = useState(false);

  // DLQ Detail Modal
  const [selectedDlq, setSelectedDlq] = useState<DlqRecord | null>(null);
  const [dlqModalOpen, setDlqModalOpen] = useState(false);
  const [retrying, setRetrying] = useState(false);

  const fetchParsers = async () => {
    try {
      const data = await ApiClient.listParsers();
      setParsers(data);
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

  useEffect(() => {
    fetchParsers();
    fetchDlq();
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
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
            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
              Parser Hot-Registry & Dead-Letter Queue
            </h1>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              Manage native and dynamically approved parsers without downtime, inspect DLQ diagnostics
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
            onClick={() => setActiveTab('dlq')}
            className={`btn ${activeTab === 'dlq' ? 'btn-primary' : 'btn-ghost'}`}
            style={{ fontSize: '0.8125rem', padding: '0.45rem 0.95rem' }}
          >
            <AlertOctagon size={14} />
            <span>DLQ Inspector ({dlqEntries.length})</span>
          </button>
        </div>
      </div>

      {/* Active Parsers Tab */}
      {activeTab === 'parsers' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Registered Parser Engine Plugins
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Hot-registration enabled • Zero restart required
            </span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem', textAlign: 'left' }}>
              <thead>
                <tr style={{ backgroundColor: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Parser Identifier</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Display Name</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Format</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Version</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Type</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Status</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700, textAlign: 'right' }}>Active Toggle</th>
                </tr>
              </thead>
              <tbody>
                {parsers.map((p) => (
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
                      <span
                        className={`badge ${p.parserType === 'DYNAMIC_INFERRED' ? 'badge-warning' : 'badge-success'}`}
                        style={{ fontSize: '0.65rem' }}
                      >
                        {p.parserType}
                      </span>
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
                      <button
                        onClick={() => handleToggleParser(p.name, p.active)}
                        className={`btn ${p.active ? 'btn-secondary' : 'btn-primary'}`}
                        style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}
                      >
                        {p.active ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Dead-Letter Queue (DLQ) Inspector Tab */}
      {activeTab === 'dlq' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Dead-Letter Queue (DLQ) Diagnostic Records
            </span>
            <button
              onClick={fetchDlq}
              className="btn btn-ghost"
              style={{ fontSize: '0.75rem' }}
            >
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
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Retries</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Status</th>
                  <th style={{ padding: '0.75rem 1rem', fontWeight: 700, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {dlqEntries.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '3rem', color: 'var(--status-success)' }}>
                      <CheckCircle2 size={24} style={{ display: 'block', margin: '0 auto 0.5rem' }} />
                      Dead-Letter Queue is empty. All perimeter events normalized successfully!
                    </td>
                  </tr>
                ) : (
                  dlqEntries.map((d) => (
                    <tr key={d.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-secondary)' }}>
                        {d.createdAt ? d.createdAt.substring(0, 19).replace('T', ' ') : '—'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)' }}>
                        {d.rawEventId}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="badge badge-danger" style={{ fontSize: '0.65rem' }}>{d.failureCode}</span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-primary)', maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {d.failureReason}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace' }}>
                        {d.retryCount}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          className={`badge ${
                            d.status === 'NEW' ? 'badge-warning' : d.status.startsWith('RESOLVED') ? 'badge-success' : 'badge-info'
                          }`}
                          style={{ fontSize: '0.65rem' }}
                        >
                          {d.status}
                        </span>
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
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* DLQ Inspector Modal */}
      <Modal
        isOpen={dlqModalOpen}
        onClose={() => setDlqModalOpen(false)}
        title={`DLQ Diagnostic Record #${selectedDlq?.id || ''}`}
        maxWidth="750px"
      >
        {selectedDlq && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8125rem' }}>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.7rem' }}>Failure Code:</span>
                <span className="badge badge-danger" style={{ marginTop: '0.2rem' }}>{selectedDlq.failureCode}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.7rem' }}>Detected Format:</span>
                <span className="badge badge-info" style={{ marginTop: '0.2rem' }}>{selectedDlq.detectedFormat}</span>
              </div>
            </div>

            <div>
              <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.7rem', marginBottom: '0.25rem' }}>Failure Reason:</span>
              <div style={{ backgroundColor: 'var(--bg-tertiary)', padding: '0.6rem 0.85rem', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontSize: '0.8rem' }}>
                {selectedDlq.failureReason}
              </div>
            </div>

            <div>
              <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.7rem', marginBottom: '0.25rem' }}>Raw Unprocessed Payload:</span>
              <div
                style={{
                  backgroundColor: 'var(--bg-code)',
                  padding: '0.75rem',
                  borderRadius: 'var(--radius-md)',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '0.75rem',
                  color: '#e2e8f0',
                  maxHeight: '160px',
                  overflowY: 'auto',
                  wordBreak: 'break-all',
                }}
              >
                {selectedDlq.rawMessage}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.75rem' }}>
              <button
                onClick={() => handleResolveDlq(selectedDlq.id, 'DISCARDED')}
                className="btn btn-ghost"
                style={{ color: 'var(--status-danger)', fontSize: '0.75rem' }}
              >
                Discard Entry
              </button>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button
                  onClick={() => handleResolveDlq(selectedDlq.id, 'RESOLVED_MANUALLY')}
                  className="btn btn-secondary"
                  style={{ fontSize: '0.75rem' }}
                >
                  Mark Resolved
                </button>
                <button
                  onClick={() => handleRetryDlq(selectedDlq.id)}
                  disabled={retrying}
                  className="btn btn-primary"
                  style={{ fontSize: '0.75rem' }}
                >
                  <RotateCcw size={14} />
                  <span>{retrying ? 'Retrying...' : 'Re-Ingest Through Pipeline'}</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
