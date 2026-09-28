import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { wsService } from '../api/websocket';
import { NormalizedEventRecord, IntegrityCheckResponse, OcsfEvent } from '../api/types';
import { ConfidenceBadge } from '../components/ConfidenceBadge';
import { JsonViewer } from '../components/JsonViewer';
import { Modal } from '../components/Modal';
import {
  Radio,
  Search,
  Filter,
  ShieldCheck,
  ShieldAlert,
  Eye,
  RefreshCw,
  Lock,
  Layers,
  CheckCircle,
  XCircle,
  Hash,
  AlertTriangle,
} from 'lucide-react';

export const LiveStreamViewer: React.FC = () => {
  const [events, setEvents] = useState<NormalizedEventRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [paused, setPaused] = useState(false);

  // Filters
  const [sourceIp, setSourceIp] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [formatFilter, setFormatFilter] = useState('');

  // Selected Event Inspector State
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEventRecord | null>(null);
  const [rawEventData, setRawEventData] = useState<any | null>(null);
  const [parsedOcsf, setParsedOcsf] = useState<OcsfEvent | null>(null);
  const [inspectModalOpen, setInspectModalOpen] = useState(false);

  // Cryptographic Integrity State
  const [verifying, setVerifying] = useState(false);
  const [integrityResult, setIntegrityResult] = useState<IntegrityCheckResponse | null>(null);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = {};
      if (sourceIp.trim()) params.sourceIp = sourceIp.trim();
      if (actionFilter) params.action = actionFilter;
      if (severityFilter) params.severity = severityFilter;
      if (formatFilter) params.format = formatFilter;

      const res = await ApiClient.searchEvents(params);
      setEvents(res.content || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();

    const unsub = wsService.onEvent((newEvent: OcsfEvent) => {
      if (!paused) {
        // Prepend incoming live event to stream table (deduplicated by eventId)
        setEvents((prev) => {
          if (newEvent.eventId && prev.some((e) => e.eventId === newEvent.eventId)) {
            return prev;
          }
          const rec: NormalizedEventRecord = {
            id: Date.now(),
            eventId: newEvent.eventId,
            rawEventId: newEvent.rawEventId,
            rawHashSha256: newEvent.rawHashSha256,
            timestampUtc: newEvent.timestampUtc,
            category: newEvent.event?.category || 'network_traffic',
            eventType: newEvent.event?.type || 'firewall',
            action: newEvent.event?.action || 'allowed',
            severity: newEvent.event?.severity || 'informational',
            sourceIp: newEvent.source?.ip || '',
            sourcePort: newEvent.source?.port,
            destinationIp: newEvent.destination?.ip || '',
            destinationPort: newEvent.destination?.port,
            protocol: newEvent.network?.protocol || 'TCP',
            observerVendor: newEvent.observer?.vendor || 'Gateway',
            observerProduct: newEvent.observer?.product || 'ULPF',
            parserName: newEvent.ulpf?.parserName || 'native',
            parserVersion: newEvent.ulpf?.parserVersion || '1.0',
            averageConfidence: newEvent.ulpf?.averageConfidence || 0.95,
            format: newEvent.raw?.format || 'SYSLOG',
            ocsfJson: JSON.stringify(newEvent),
            processedAt: new Date().toISOString(),
          };
          return [rec, ...prev.slice(0, 49)];
        });
      }
    });

    return () => {
      unsub();
    };
  }, [paused]);

  const [merkleResult, setMerkleResult] = useState<any | null>(null);
  const [verifyingMerkle, setVerifyingMerkle] = useState(false);

  const handleOpenInspector = async (record: NormalizedEventRecord) => {
    setSelectedEvent(record);
    setIntegrityResult(null);
    setMerkleResult(null);
    setInspectModalOpen(true);

    try {
      const ocsfObj = JSON.parse(record.ocsfJson);
      setParsedOcsf(ocsfObj);
    } catch {
      setParsedOcsf(null);
    }

    try {
      const raw = await ApiClient.getRawEvent(record.eventId);
      setRawEventData(raw);
    } catch {
      setRawEventData(null);
    }
  };

  const handleVerifyIntegrity = async (eventId: string) => {
    setVerifying(true);
    setIntegrityResult(null);
    try {
      const res = await ApiClient.verifyIntegrity(eventId);
      setIntegrityResult(res);
    } catch (e: any) {
      alert('Integrity audit failed: ' + e.message);
    } finally {
      setVerifying(false);
    }
  };

  const handleVerifyMerkle = async (eventId: string) => {
    setVerifyingMerkle(true);
    setMerkleResult(null);
    try {
      const res = await ApiClient.verifyMerkleInclusion(eventId);
      setMerkleResult(res);
    } catch (e: any) {
      alert('Merkle proof verification failed: ' + e.message);
    } finally {
      setVerifyingMerkle(false);
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
            <Radio size={24} />
          </div>
          <div>
            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
              Live Stream & Cryptographic Lineage Viewer
            </h1>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              Real-time normalized event stream, side-by-side raw comparison, and SHA-256 integrity verification
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            onClick={() => setPaused(!paused)}
            className="btn btn-secondary"
            style={{ fontSize: '0.8125rem' }}
          >
            {paused ? 'Resume Stream' : 'Pause Live Feed'}
          </button>
          <button
            onClick={fetchEvents}
            className="btn btn-secondary"
            style={{ fontSize: '0.8125rem' }}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card p-4" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Source IP
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type="text"
                className="input font-mono"
                style={{ fontSize: '0.8125rem', paddingLeft: '2rem' }}
                placeholder="e.g. 192.168.1.5"
                value={sourceIp}
                onChange={(e) => setSourceIp(e.target.value)}
              />
              <Search size={14} style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Action
            </label>
            <select
              className="input"
              style={{ fontSize: '0.8125rem' }}
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
            >
              <option value="">All Actions</option>
              <option value="allowed">Allowed</option>
              <option value="blocked">Blocked / Denied</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Severity
            </label>
            <select
              className="input"
              style={{ fontSize: '0.8125rem' }}
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Format
            </label>
            <select
              className="input"
              style={{ fontSize: '0.8125rem' }}
              value={formatFilter}
              onChange={(e) => setFormatFilter(e.target.value)}
            >
              <option value="">All Formats</option>
              <option value="SYSLOG">Syslog (RFC5424/3164)</option>
              <option value="CEF">CEF</option>
              <option value="LEEF">LEEF</option>
              <option value="JSON">JSON</option>
              <option value="CSV">CSV</option>
              <option value="CUSTOM">Custom Inferred</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-end' }}>
            <button
              onClick={fetchEvents}
              className="btn btn-primary"
              style={{ width: '100%', fontSize: '0.8125rem' }}
            >
              <Filter size={14} />
              <span>Apply Filters</span>
            </button>
          </div>
        </div>
      </div>

      {/* Live Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ backgroundColor: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Timestamp (UTC)</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Event ID</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Format</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Source</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Destination</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Action</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 700 }}>Confidence</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 700, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                    No events matched filters.
                  </td>
                </tr>
              ) : (
                events.map((evt) => (
                  <tr
                    key={evt.eventId}
                    style={{ borderBottom: '1px solid var(--border-color)', transition: 'background-color 0.15s' }}
                    className="card-interactive"
                  >
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-secondary)' }}>
                      {evt.timestampUtc ? evt.timestampUtc.substring(0, 19).replace('T', ' ') : '—'}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                      {evt.eventId.substring(0, 16)}...
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>{evt.format}</span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace' }}>
                      {evt.sourceIp || '—'}{evt.sourcePort ? `:${evt.sourcePort}` : ''}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace' }}>
                      {evt.destinationIp || '—'}{evt.destinationPort ? `:${evt.destinationPort}` : ''}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span
                        className={`badge ${evt.action === 'blocked' ? 'badge-danger' : 'badge-success'}`}
                        style={{ fontSize: '0.65rem' }}
                      >
                        {evt.action}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <ConfidenceBadge confidence={evt.averageConfidence} size="sm" />
                    </td>
                    <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                      <button
                        onClick={() => handleOpenInspector(evt)}
                        className="btn btn-secondary"
                        style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem' }}
                      >
                        <Eye size={14} />
                        <span>Inspect & Audit</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Side-by-Side Raw vs Normalized OCSF Inspector & SHA-256 Audit Modal */}
      <Modal
        isOpen={inspectModalOpen}
        onClose={() => setInspectModalOpen(false)}
        title={`Event Cryptographic Audit: ${selectedEvent?.eventId || ''}`}
        maxWidth="900px"
      >
        {selectedEvent && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Top Cryptographic Hash Bar */}
            <div
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                padding: '0.85rem 1rem',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border-color)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '0.75rem',
              }}
            >
              <div>
                <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Pre-Parse SHA-256 Digest:
                </span>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>
                  {selectedEvent.rawHashSha256}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button
                  onClick={() => handleVerifyIntegrity(selectedEvent.eventId)}
                  disabled={verifying}
                  className="btn btn-secondary"
                  style={{ fontSize: '0.75rem', padding: '0.45rem 0.85rem' }}
                >
                  <ShieldCheck size={14} />
                  <span>{verifying ? 'Auditing...' : 'Verify SHA-256 Digest'}</span>
                </button>
                <button
                  onClick={() => handleVerifyMerkle(selectedEvent.eventId)}
                  disabled={verifyingMerkle}
                  className="btn btn-primary"
                  style={{ fontSize: '0.75rem', padding: '0.45rem 0.85rem' }}
                >
                  <Lock size={14} />
                  <span>{verifyingMerkle ? 'Verifying Tree...' : 'Verify Merkle Inclusion'}</span>
                </button>
              </div>
            </div>

            {/* Integrity Audit Result Banner */}
            {integrityResult && (
              <div
                style={{
                  padding: '1rem',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: integrityResult.verified ? 'var(--status-success-bg)' : 'var(--status-danger-bg)',
                  border: `1px solid ${integrityResult.verified ? 'rgba(0, 230, 118, 0.4)' : 'rgba(255, 61, 113, 0.4)'}`,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                  {integrityResult.verified ? (
                    <CheckCircle size={18} color="var(--status-success)" />
                  ) : (
                    <XCircle size={18} color="var(--status-danger)" />
                  )}
                  <span style={{ fontSize: '0.9rem', fontWeight: 800, color: integrityResult.verified ? 'var(--status-success)' : 'var(--status-danger)' }}>
                    {integrityResult.verified ? 'NON-REPUDIATION VERIFIED' : 'INTEGRITY AUDIT FAILED'}
                  </span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                  {integrityResult.statusMessage}
                </p>
                <div style={{ fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-secondary)' }}>
                  Stored Hash: <strong>{integrityResult.storedRawHash}</strong><br />
                  Recomputed: <strong>{integrityResult.recomputedRawHash}</strong><br />
                  Raw Byte Size: <strong>{integrityResult.rawByteLength} bytes</strong> • Lineage: <strong>{integrityResult.parserName} (v{integrityResult.parserVersion})</strong>
                </div>
              </div>
            )}

            {/* Merkle Inclusion Proof Banner */}
            {merkleResult && (
              <div
                style={{
                  padding: '1rem',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: merkleResult.verified ? 'var(--status-success-bg)' : 'var(--status-warning-bg)',
                  border: `1px solid ${merkleResult.verified ? 'rgba(0, 230, 118, 0.4)' : 'rgba(255, 171, 0, 0.4)'}`,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                  {merkleResult.verified ? (
                    <CheckCircle size={18} color="var(--status-success)" />
                  ) : (
                    <AlertTriangle size={18} color="var(--status-warning)" />
                  )}
                  <span style={{ fontSize: '0.9rem', fontWeight: 800, color: merkleResult.verified ? 'var(--status-success)' : 'var(--status-warning)' }}>
                    {merkleResult.verified ? 'MERKLE TREE INCLUSION PROOF VERIFIED' : 'MERKLE INCLUSION PENDING'}
                  </span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                  {merkleResult.statusMessage}
                </p>
                {merkleResult.verified && (
                  <div style={{ fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-secondary)' }}>
                    Batch ID: <strong>{merkleResult.merkleBatchId}</strong> • Leaf Index: <strong>#{merkleResult.leafIndex}</strong> of <strong>{merkleResult.totalLeaves}</strong><br />
                    Merkle Root: <strong>{merkleResult.merkleRoot}</strong><br />
                    Proof Path Depth: <strong>{merkleResult.proofPath?.length || 0} sibling nodes</strong>
                  </div>
                )}
              </div>
            )}

            {/* Side-by-Side: Raw String vs Normalized OCSF JSON */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: '1rem' }}>
              {/* Raw String */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Original Bit-Exact Raw Event:
                </span>
                <div
                  style={{
                    backgroundColor: 'var(--bg-code)',
                    padding: '0.85rem',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border-color)',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '0.8rem',
                    color: '#e2e8f0',
                    minHeight: '280px',
                    maxHeight: '380px',
                    overflowY: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                  }}
                >
                  {rawEventData?.rawMessage || selectedEvent.ocsfJson}
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  Ingestion Source: <strong>{rawEventData?.ingestionSource || 'GATEWAY_STREAM'}</strong> • Raw ID: <strong>{selectedEvent.rawEventId}</strong>
                </div>
              </div>

              {/* Normalized Canonical OCSF */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Canonical OCSF v1.1.0 Event:
                </span>
                <JsonViewer
                  data={parsedOcsf || selectedEvent.ocsfJson}
                  title="Normalized OCSF Representation"
                  maxHeight="380px"
                />
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
