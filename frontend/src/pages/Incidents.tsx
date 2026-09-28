import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { CorrelatedIncident, IncidentDetailResponse } from '../api/types';
import { Modal } from '../components/Modal';
import {
  Link2,
  ShieldAlert,
  Flame,
  Clock,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Play,
  ArrowRight,
  Eye,
  Check,
  Search,
  Filter,
  Layers,
  Sparkles,
  ChevronDown,
  ChevronUp,
  Cpu,
  Terminal,
} from 'lucide-react';

const ORDERED_MITRE_TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

export const Incidents: React.FC = () => {
  const [incidents, setIncidents] = useState<CorrelatedIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [scanning, setScanning] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [incidentDetails, setIncidentDetails] = useState<Record<number, IncidentDetailResponse>>({});
  const [loadingDetailId, setLoadingDetailId] = useState<number | null>(null);
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  const currentUser = ApiClient.getCurrentUser();
  const isAdmin = currentUser?.role === 'ADMIN';

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const data = await ApiClient.listIncidents(statusFilter === 'ALL' ? undefined : statusFilter);
      setIncidents(data);
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to fetch incidents: ' + err.message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [statusFilter]);

  const handleTriggerScan = async () => {
    try {
      setScanning(true);
      setStatusMsg(null);
      const res = await ApiClient.triggerCorrelation(30);
      setStatusMsg({
        type: 'success',
        text: `Correlation scan completed. Evaluated 30m window: ${res.incidentsCreatedOrUpdated} incident(s) promoted/updated.`,
      });
      await fetchIncidents();
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to trigger scan: ' + err.message });
    } finally {
      setScanning(false);
    }
  };

  const handleToggleExpand = async (incident: CorrelatedIncident) => {
    if (expandedId === incident.id) {
      setExpandedId(null);
      return;
    }

    setExpandedId(incident.id);
    if (!incidentDetails[incident.id]) {
      try {
        setLoadingDetailId(incident.id);
        const detail = await ApiClient.getIncident(incident.id);
        setIncidentDetails((prev) => ({ ...prev, [incident.id]: detail }));
      } catch (err: any) {
        console.error('Failed to load incident member details', err);
      } finally {
        setLoadingDetailId(null);
      }
    }
  };

  const handleStatusChange = async (incidentId: number, newStatus: string) => {
    try {
      const updated = await ApiClient.updateIncidentStatus(incidentId, newStatus);
      setIncidents((prev) => prev.map((inc) => (inc.id === incidentId ? updated : inc)));
      setStatusMsg({ type: 'success', text: `Incident ${updated.incidentKey} status changed to ${newStatus}` });
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to update status: ' + err.message });
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL': return 'badge-danger';
      case 'HIGH': return 'badge-warning';
      case 'MEDIUM': return 'badge-info';
      default: return 'badge-neutral';
    }
  };

  const parseTacticChain = (jsonStr: string): string[] => {
    try {
      return JSON.parse(jsonStr || '[]');
    } catch {
      return [];
    }
  };

  const openCount = incidents.filter((i) => i.status === 'OPEN').length;
  const investigatingCount = incidents.filter((i) => i.status === 'INVESTIGATING').length;

  return (
    <div className="container" style={{ padding: '2rem 1.5rem', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '2rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
            <h1 style={{ margin: 0, fontSize: '1.75rem', fontWeight: 800, color: 'var(--text-primary)' }}>
              Auto Root-Cause Correlation Engine
            </h1>
            <span className="badge badge-success" style={{ fontSize: '0.75rem' }}>
              <Link2 size={12} /> DETERMINISTIC KILL-CHAIN
            </span>
            <span className="badge badge-info" style={{ fontSize: '0.75rem' }}>
              <Terminal size={12} /> ZERO MACHINE LEARNING
            </span>
          </div>
          <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.875rem', maxWidth: '850px' }}>
            Automated correlation of isolated Sigma detections and MITRE-tagged telemetry into multi-stage attack incidents. Generates deterministic narrative hypotheses and horizontal kill-chain timelines based on shared entities and sliding time windows.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button
            onClick={fetchIncidents}
            className="btn btn-secondary"
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <RefreshCw size={16} className={loading ? 'spin' : ''} /> Refresh
          </button>
          {isAdmin && (
            <button
              onClick={handleTriggerScan}
              className="btn btn-primary"
              disabled={scanning}
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            >
              <Link2 size={16} />
              {scanning ? 'Correlating Window...' : 'Trigger Correlation Scan'}
            </button>
          )}
        </div>
      </div>

      {/* Status Alert Banner */}
      {statusMsg && (
        <div
          style={{
            padding: '0.875rem 1.25rem',
            borderRadius: 'var(--radius-md)',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            backgroundColor: statusMsg.type === 'error' ? 'var(--status-danger-bg)' : statusMsg.type === 'success' ? 'var(--status-success-bg)' : 'var(--status-info-bg)',
            color: statusMsg.type === 'error' ? 'var(--status-danger)' : statusMsg.type === 'success' ? 'var(--status-success)' : 'var(--accent-cyan)',
            border: `1px solid ${statusMsg.type === 'error' ? 'var(--status-danger)' : statusMsg.type === 'success' ? 'var(--status-success)' : 'var(--accent-cyan)'}`,
          }}
        >
          {statusMsg.type === 'error' ? <AlertTriangle size={18} /> : <Check size={18} />}
          <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>{statusMsg.text}</span>
        </div>
      )}

      {/* KPI Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
            Open Incidents
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: openCount > 0 ? 'var(--status-danger)' : 'var(--status-success)' }}>
            {openCount}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Spanning $\ge 2$ distinct tactics
          </div>
        </div>

        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
            Under Investigation
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--status-warning)' }}>
            {investigatingCount}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Assigned analyst triage
          </div>
        </div>

        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
            Correlation Window
          </div>
          <div style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono, monospace' }}>
            30 Minutes
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Sliding window evaluator
          </div>
        </div>

        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
            Root Cause Model
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            Earliest Initiating Event
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Heuristic hypothesis only
          </div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border-color)', marginBottom: '1.5rem' }}>
        {['ALL', 'OPEN', 'INVESTIGATING', 'CLOSED'].map((tab) => (
          <button
            key={tab}
            onClick={() => setStatusFilter(tab)}
            className={`btn ${statusFilter === tab ? 'btn-primary' : 'btn-ghost'}`}
            style={{ borderBottomLeftRadius: 0, borderBottomRightRadius: 0, fontSize: '0.8125rem' }}
          >
            {tab} {tab === 'OPEN' && openCount > 0 && `(${openCount})`}
          </button>
        ))}
      </div>

      {/* Incidents List */}
      {loading ? (
        <div className="card" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          <RefreshCw size={24} className="spin" style={{ margin: '0 auto 1rem' }} />
          <div>Loading correlated multi-stage incidents...</div>
        </div>
      ) : incidents.length === 0 ? (
        <div className="card" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          <CheckCircle2 size={36} style={{ margin: '0 auto 1rem', color: 'var(--status-success)' }} />
          <div style={{ fontWeight: 600 }}>No Correlated Attack Incidents Found</div>
          <p style={{ fontSize: '0.875rem', marginTop: '0.25rem' }}>
            Incidents will automatically generate when multiple detections from the same source span 2 or more distinct MITRE tactics within the 30-minute window.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {incidents.map((inc) => {
            const isExpanded = expandedId === inc.id;
            const tactics = parseTacticChain(inc.tacticChain);
            const detail = incidentDetails[inc.id];

            return (
              <div key={inc.id} className="card" style={{ overflow: 'hidden', borderLeft: `4px solid ${inc.severity === 'CRITICAL' ? 'var(--status-danger)' : inc.severity === 'HIGH' ? 'var(--status-warning)' : 'var(--accent-cyan)'}` }}>
                {/* Summary Header Row */}
                <div style={{ padding: '1.25rem 1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <span className={`badge ${getSeverityBadge(inc.severity)}`} style={{ textTransform: 'uppercase', fontWeight: 800, fontSize: '0.75rem' }}>
                      {inc.severity}
                    </span>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, fontSize: '1rem', color: 'var(--accent-cyan)' }}>
                          {inc.incidentKey}
                        </span>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>•</span>
                        <span style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)' }}>
                          {inc.keyType}: <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{inc.correlationKey}</span>
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                        Spans <strong>{inc.distinctTacticCount} distinct tactics</strong> across <strong>{inc.eventCount} detection events</strong>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    {/* Status badge & Controls */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className={`badge ${inc.status === 'OPEN' ? 'badge-danger' : inc.status === 'INVESTIGATING' ? 'badge-warning' : 'badge-neutral'}`}>
                        {inc.status}
                      </span>
                      {inc.status === 'OPEN' && (
                        <button
                          onClick={() => handleStatusChange(inc.id, 'INVESTIGATING')}
                          className="btn btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
                        >
                          Investigate
                        </button>
                      )}
                      {inc.status !== 'CLOSED' && (
                        <button
                          onClick={() => handleStatusChange(inc.id, 'CLOSED')}
                          className="btn btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
                        >
                          Close
                        </button>
                      )}
                      {inc.status === 'CLOSED' && (
                        <button
                          onClick={() => handleStatusChange(inc.id, 'OPEN')}
                          className="btn btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
                        >
                          Reopen
                        </button>
                      )}
                    </div>

                    <button
                      onClick={() => handleToggleExpand(inc)}
                      className="btn btn-primary"
                      style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                    >
                      {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                      {isExpanded ? 'Hide Attack Story' : 'Inspect Attack Story'}
                    </button>
                  </div>
                </div>

                {/* Expanded Story & Timeline */}
                {isExpanded && (
                  <div style={{ padding: '1.25rem 1.5rem', borderTop: '1px solid var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
                    {/* Horizontal Kill-Chain Timeline */}
                    <div style={{ marginBottom: '1.5rem' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.75rem' }}>
                        MITRE Enterprise Kill-Chain Progression (Ordered Sequence)
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', overflowX: 'auto', padding: '0.75rem 0.5rem', gap: '0.25rem' }}>
                        {ORDERED_MITRE_TACTICS.map((tactic, idx) => {
                          const isMatched = tactics.some((t) => t.toLowerCase() === tactic.toLowerCase());
                          return (
                            <React.Fragment key={tactic}>
                              <div
                                style={{
                                  display: 'flex',
                                  flexDirection: 'column',
                                  alignItems: 'center',
                                  minWidth: '100px',
                                  textAlign: 'center',
                                  opacity: isMatched ? 1 : 0.35,
                                }}
                              >
                                <div
                                  style={{
                                    width: isMatched ? '24px' : '16px',
                                    height: isMatched ? '24px' : '16px',
                                    borderRadius: '50%',
                                    backgroundColor: isMatched ? 'var(--status-danger)' : 'var(--border-color)',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    color: '#fff',
                                    fontSize: '0.7rem',
                                    fontWeight: 800,
                                    boxShadow: isMatched ? '0 0 10px rgba(255, 61, 113, 0.6)' : 'none',
                                    marginBottom: '0.35rem',
                                  }}
                                >
                                  {isMatched ? '✓' : idx + 1}
                                </div>
                                <span style={{ fontSize: '0.65rem', fontWeight: isMatched ? 800 : 500, color: isMatched ? 'var(--text-primary)' : 'var(--text-muted)', lineHeight: '1.2' }}>
                                  {tactic}
                                </span>
                              </div>
                              {idx < ORDERED_MITRE_TACTICS.length - 1 && (
                                <div
                                  style={{
                                    flex: 1,
                                    height: '2px',
                                    minWidth: '20px',
                                    backgroundColor: isMatched ? 'var(--status-danger)' : 'var(--border-color)',
                                    opacity: isMatched ? 0.8 : 0.3,
                                  }}
                                />
                              )}
                            </React.Fragment>
                          );
                        })}
                      </div>
                    </div>

                    {/* Probable Root Cause Hypothesis Card */}
                    <div
                      style={{
                        padding: '1rem 1.25rem',
                        borderRadius: 'var(--radius-md)',
                        backgroundColor: 'var(--bg-tertiary)',
                        border: '1px solid var(--accent-cyan)',
                        marginBottom: '1.25rem',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                        <Sparkles size={18} style={{ color: 'var(--accent-cyan)' }} />
                        <span style={{ fontWeight: 800, fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                          Probable Root Cause (earliest event in chain — heuristic hypothesis)
                        </span>
                      </div>
                      <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                        Earliest Initiating Event ID: <strong style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)' }}>{inc.rootEventId}</strong> • First Seen: <strong>{new Date(inc.firstSeenAt).toISOString().replace('T', ' ').substring(0, 19)} UTC</strong>
                      </div>
                      <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                        * Note: This root cause is an automated heuristic hypothesis representing the earliest observed attack signature in the correlated window. It is not a proven causal certainty and should be validated by an analyst.
                      </p>
                    </div>

                    {/* Narrative Description Box */}
                    <div style={{ marginBottom: '1.25rem' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
                        Correlated Attack Narrative
                      </div>
                      <div
                        style={{
                          backgroundColor: 'var(--bg-primary)',
                          padding: '1rem',
                          borderRadius: 'var(--radius-md)',
                          border: '1px solid var(--border-color)',
                          fontFamily: 'JetBrains Mono, monospace',
                          fontSize: '0.8125rem',
                          lineHeight: '1.5',
                          color: 'var(--text-primary)',
                        }}
                      >
                        {inc.narrativeText}
                      </div>
                    </div>

                    {/* Member Events Table */}
                    {loadingDetailId === inc.id ? (
                      <div style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-muted)' }}>
                        <RefreshCw size={16} className="spin" /> Loading member detections...
                      </div>
                    ) : detail && detail.memberEvents ? (
                      <div>
                        <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
                          Correlated Member Detections ({detail.memberEvents.length})
                        </div>
                        <div style={{ maxHeight: '240px', overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)' }}>
                          <table className="table" style={{ width: '100%', fontSize: '0.75rem' }}>
                            <thead>
                              <tr>
                                <th style={{ padding: '0.5rem' }}>Timestamp</th>
                                <th style={{ padding: '0.5rem' }}>Event ID</th>
                                <th style={{ padding: '0.5rem' }}>Technique / Tactic</th>
                                <th style={{ padding: '0.5rem' }}>Matched Rule / Event</th>
                                <th style={{ padding: '0.5rem' }}>Destination</th>
                              </tr>
                            </thead>
                            <tbody>
                              {detail.memberEvents.map((me) => (
                                <tr key={me.eventId} style={{ borderBottom: '1px solid var(--border-color)' }}>
                                  <td style={{ padding: '0.5rem', color: 'var(--text-secondary)' }}>
                                    {me.timestamp ? new Date(me.timestamp).toISOString().replace('T', ' ').substring(0, 19) : '—'}
                                  </td>
                                  <td style={{ padding: '0.5rem', fontFamily: 'JetBrains Mono, monospace', color: me.eventId === inc.rootEventId ? 'var(--accent-cyan)' : 'inherit', fontWeight: me.eventId === inc.rootEventId ? 800 : 500 }}>
                                    {me.eventId} {me.eventId === inc.rootEventId && '(Root)'}
                                  </td>
                                  <td style={{ padding: '0.5rem' }}>
                                    <strong>{me.techniqueId || '—'}</strong> ({me.tactic || 'General'})
                                  </td>
                                  <td style={{ padding: '0.5rem' }}>
                                    {me.matchedRules && me.matchedRules.length > 0 ? me.matchedRules.join(', ') : 'Telemetry Event'}
                                  </td>
                                  <td style={{ padding: '0.5rem', fontFamily: 'JetBrains Mono, monospace' }}>
                                    {me.destinationIp ? `${me.destinationIp}${me.destinationPort ? `:${me.destinationPort}` : ''}` : '—'}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    ) : null}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
