import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { SigmaRule, SigmaMatch } from '../api/types';
import { Modal } from '../components/Modal';
import {
  ShieldAlert,
  Flame,
  FileCode,
  Plus,
  RefreshCw,
  Check,
  AlertTriangle,
  Play,
  ToggleLeft,
  ToggleRight,
  Trash2,
  Terminal,
  Activity,
  Layers,
  Filter,
} from 'lucide-react';

const DEFAULT_SAMPLE_YAML = `title: Detect Suspicious High-Port Inbound Traffic
id: SIGMA-CUSTOM-PORT-001
status: production
description: Detects inbound connection attempts on non-standard high ports.
level: medium
tags:
  - attack.t1071
  - attack.command_and_control
logsource:
  category: network_traffic
detection:
  selection:
    destination.port:
      - 8888
      - 9999
    event.action:
      - blocked
      - denied
  condition: selection
`;

export const DetectionRules: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'rules' | 'create' | 'matches'>('rules');
  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [matches, setMatches] = useState<SigmaMatch[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedRule, setSelectedRule] = useState<SigmaRule | null>(null);
  const [yamlInput, setYamlInput] = useState(DEFAULT_SAMPLE_YAML);
  const [creating, setCreating] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  const currentUser = ApiClient.getCurrentUser();
  const isAdmin = currentUser?.role === 'ADMIN';

  const fetchRulesAndMatches = async () => {
    try {
      setLoading(true);
      const [rulesData, matchesData] = await Promise.all([
        ApiClient.listSigmaRules(),
        ApiClient.listAlerts({ size: 50 }),
      ]);
      setRules(rulesData);
      setMatches(matchesData.content || []);
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to load Sigma data: ' + err.message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRulesAndMatches();
  }, []);

  const handleToggleRule = async (rule: SigmaRule) => {
    try {
      const updated = await ApiClient.updateSigmaRule(rule.id, { enabled: !rule.enabled });
      setRules(rules.map((r) => (r.id === rule.id ? updated : r)));
      setStatusMsg({ type: 'success', text: `Rule ${rule.title} ${updated.enabled ? 'Enabled' : 'Disabled'}` });
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to update rule state: ' + err.message });
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    if (!window.confirm('Are you sure you want to delete this Sigma rule?')) return;
    try {
      await ApiClient.deleteSigmaRule(ruleId);
      setRules(rules.filter((r) => r.id !== ruleId));
      setStatusMsg({ type: 'success', text: 'Sigma rule deleted successfully' });
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to delete rule: ' + err.message });
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!yamlInput.trim()) return;
    try {
      setCreating(true);
      setStatusMsg(null);
      const newRule = await ApiClient.createSigmaRule(yamlInput);
      setStatusMsg({ type: 'success', text: `Successfully registered Sigma Rule: ${newRule.title} [${newRule.id}]` });
      setActiveTab('rules');
      await fetchRulesAndMatches();
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to parse/save Sigma rule: ' + err.message });
    } finally {
      setCreating(false);
    }
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'badge-danger';
      case 'high': return 'badge-warning';
      case 'medium': return 'badge-info';
      default: return 'badge-neutral';
    }
  };

  const filteredMatches = matches.filter((m) => {
    if (severityFilter !== 'ALL' && m.severity?.toUpperCase() !== severityFilter) return false;
    return true;
  });

  return (
    <div className="container" style={{ padding: '2rem 1.5rem', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '2rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
            <h1 style={{ margin: 0, fontSize: '1.75rem', fontWeight: 800, color: 'var(--text-primary)' }}>
              Embedded Sigma Detection Rule Engine
            </h1>
            <span className="badge badge-danger" style={{ fontSize: '0.75rem' }}>
              <Flame size={12} /> LIVE DETECTIONS
            </span>
            <span className="badge badge-info" style={{ fontSize: '0.75rem' }}>
              <Terminal size={12} /> AIR-GAPPED EVALUATOR
            </span>
          </div>
          <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.875rem', maxWidth: '800px' }}>
            Real-time evaluation of canonical OCSF telemetry against standardized Sigma threat detection rules. Automatically detects perimeter attacks, brute-force attempts, and suspicious command-and-control communication.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button
            onClick={fetchRulesAndMatches}
            className="btn btn-secondary"
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <RefreshCw size={16} className={loading ? 'spin' : ''} /> Refresh
          </button>
          {isAdmin && (
            <button
              onClick={() => setActiveTab('create')}
              className="btn btn-primary"
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            >
              <Plus size={16} /> New Sigma Rule
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

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border-color)', marginBottom: '1.5rem' }}>
        <button
          onClick={() => setActiveTab('rules')}
          className={`btn ${activeTab === 'rules' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ borderBottomLeftRadius: 0, borderBottomRightRadius: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}
        >
          <FileCode size={16} /> Active Rules ({rules.length})
        </button>
        <button
          onClick={() => setActiveTab('matches')}
          className={`btn ${activeTab === 'matches' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ borderBottomLeftRadius: 0, borderBottomRightRadius: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}
        >
          <Flame size={16} /> Live Matches Feed ({matches.length})
        </button>
        {isAdmin && (
          <button
            onClick={() => setActiveTab('create')}
            className={`btn ${activeTab === 'create' ? 'btn-primary' : 'btn-ghost'}`}
            style={{ borderBottomLeftRadius: 0, borderBottomRightRadius: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <Plus size={16} /> Create / Upload Rule
          </button>
        )}
      </div>

      {/* TAB 1: RULES LIST */}
      {activeTab === 'rules' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Rule Title & ID</th>
                  <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Technique / Tactic</th>
                  <th style={{ textAlign: 'center', padding: '0.875rem 1rem' }}>Severity</th>
                  <th style={{ textAlign: 'center', padding: '0.875rem 1rem' }}>Status</th>
                  <th style={{ textAlign: 'right', padding: '0.875rem 1rem' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} style={{ borderBottom: '1px solid var(--border-color)', opacity: rule.enabled ? 1 : 0.6 }}>
                    <td style={{ padding: '0.875rem 1rem' }}>
                      <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.875rem' }}>{rule.title}</div>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                        {rule.id}
                      </div>
                      {rule.description && (
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem', maxWidth: '400px' }}>
                          {rule.description}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '0.875rem 1rem' }}>
                      {rule.techniqueId && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginBottom: '0.25rem' }}>
                          <span className="badge badge-info" style={{ fontWeight: 700 }}>
                            {rule.techniqueId}
                          </span>
                        </div>
                      )}
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {rule.tactic || rule.logsourceCategory || 'Perimeter Security'}
                      </div>
                    </td>
                    <td style={{ padding: '0.875rem 1rem', textAlign: 'center' }}>
                      <span className={`badge ${getSeverityBadgeClass(rule.severity)}`} style={{ textTransform: 'uppercase', fontWeight: 800, fontSize: '0.7rem' }}>
                        {rule.severity}
                      </span>
                    </td>
                    <td style={{ padding: '0.875rem 1rem', textAlign: 'center' }}>
                      <span className={`badge ${rule.enabled ? 'badge-success' : 'badge-neutral'}`}>
                        {rule.enabled ? 'ACTIVE' : 'DISABLED'}
                      </span>
                    </td>
                    <td style={{ padding: '0.875rem 1rem', textAlign: 'right' }}>
                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', alignItems: 'center' }}>
                        <button
                          onClick={() => setSelectedRule(rule)}
                          className="btn btn-secondary"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                        >
                          <FileCode size={14} /> YAML
                        </button>
                        {isAdmin && (
                          <>
                            <button
                              onClick={() => handleToggleRule(rule)}
                              className="btn btn-ghost"
                              style={{ padding: '0.35rem', color: rule.enabled ? 'var(--status-success)' : 'var(--text-muted)' }}
                              title={rule.enabled ? 'Disable rule' : 'Enable rule'}
                            >
                              {rule.enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
                            </button>
                            <button
                              onClick={() => handleDeleteRule(rule.id)}
                              className="btn btn-ghost"
                              style={{ padding: '0.35rem', color: 'var(--status-danger)' }}
                              title="Delete rule"
                            >
                              <Trash2 size={16} />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: LIVE MATCHES FEED */}
      {activeTab === 'matches' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Filter size={16} style={{ color: 'var(--text-muted)' }} />
              <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Severity Filter:</span>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`btn ${severityFilter === sev ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
                >
                  {sev}
                </button>
              ))}
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Showing {filteredMatches.length} detection event{filteredMatches.length === 1 ? '' : 's'}
            </div>
          </div>

          <div className="card" style={{ overflow: 'hidden' }}>
            {filteredMatches.length === 0 ? (
              <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
                <ShieldAlert size={36} style={{ margin: '0 auto 1rem', opacity: 0.5 }} />
                <div style={{ fontWeight: 600 }}>No Sigma Detection Matches Recorded</div>
                <p style={{ fontSize: '0.875rem', marginTop: '0.25rem' }}>
                  Matches will stream live here as normalized events match enabled detection rules.
                </p>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr>
                      <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Matched Rule</th>
                      <th style={{ textAlign: 'center', padding: '0.875rem 1rem' }}>Severity</th>
                      <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Technique & Tactic</th>
                      <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Source / Destination</th>
                      <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Timestamp (UTC)</th>
                      <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Event ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredMatches.map((m) => (
                      <tr key={m.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                        <td style={{ padding: '0.875rem 1rem' }}>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.875rem' }}>{m.ruleTitle}</div>
                          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                            {m.ruleId}
                          </div>
                        </td>
                        <td style={{ padding: '0.875rem 1rem', textAlign: 'center' }}>
                          <span className={`badge ${getSeverityBadgeClass(m.severity)}`} style={{ textTransform: 'uppercase', fontWeight: 800, fontSize: '0.7rem' }}>
                            {m.severity}
                          </span>
                        </td>
                        <td style={{ padding: '0.875rem 1rem' }}>
                          {m.techniqueId && (
                            <div style={{ fontWeight: 700, fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                              {m.techniqueId}
                            </div>
                          )}
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{m.tactic || '—'}</div>
                        </td>
                        <td style={{ padding: '0.875rem 1rem', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem' }}>
                          <div>Src: {m.sourceIp || '—'}</div>
                          <div>Dst: {m.destinationIp || '—'}{m.destinationPort ? `:${m.destinationPort}` : ''}</div>
                        </td>
                        <td style={{ padding: '0.875rem 1rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                          {new Date(m.matchedAt).toISOString().replace('T', ' ').substring(0, 19)}
                        </td>
                        <td style={{ padding: '0.875rem 1rem', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {m.eventId}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: CREATE / UPLOAD RULE */}
      {activeTab === 'create' && isAdmin && (
        <div className="card" style={{ padding: '1.5rem' }}>
          <div style={{ fontWeight: 700, fontSize: '1.1rem', marginBottom: '0.5rem', color: 'var(--text-primary)' }}>
            Upload or Paste New Sigma Detection Rule
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '1.25rem' }}>
            Paste standard Sigma YAML rule syntax. The air-gapped rule engine will parse detection criteria and compile regex patterns instantly.
          </p>

          <form onSubmit={handleCreateRule}>
            <div style={{ marginBottom: '1.25rem' }}>
              <textarea
                value={yamlInput}
                onChange={(e) => setYamlInput(e.target.value)}
                rows={16}
                style={{
                  width: '100%',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '0.85rem',
                  padding: '1rem',
                  backgroundColor: 'var(--bg-tertiary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius-md)',
                  color: 'var(--text-primary)',
                  lineHeight: '1.5',
                }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => setYamlInput(DEFAULT_SAMPLE_YAML)}
                className="btn btn-secondary"
              >
                Reset to Template
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={creating}
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
              >
                <Check size={16} />
                {creating ? 'Compiling Rule...' : 'Validate & Register Rule'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Rule YAML Modal */}
      {selectedRule && (
        <Modal
          isOpen={true}
          onClose={() => setSelectedRule(null)}
          title={`Sigma Rule Definition — ${selectedRule.title}`}
        >
          <div style={{ marginBottom: '1rem' }}>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
              <span className={`badge ${getSeverityBadgeClass(selectedRule.severity)}`}>
                {selectedRule.severity.toUpperCase()}
              </span>
              {selectedRule.techniqueId && (
                <span className="badge badge-info">{selectedRule.techniqueId}</span>
              )}
            </div>
            <pre
              style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '0.8rem',
                backgroundColor: 'var(--bg-tertiary)',
                padding: '1rem',
                borderRadius: 'var(--radius-md)',
                overflowX: 'auto',
                border: '1px solid var(--border-color)',
                maxHeight: '400px',
              }}
            >
              {selectedRule.sigmaYaml}
            </pre>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button onClick={() => setSelectedRule(null)} className="btn btn-secondary">
              Close
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
};
