import React, { useState } from 'react';
import { ApiClient } from '../api/client';
import { InferenceResponse, FieldMappingItem } from '../api/types';
import { ConfidenceBadge } from '../components/ConfidenceBadge';
import { JsonViewer } from '../components/JsonViewer';
import { Modal } from '../components/Modal';
import {
  FlaskConical,
  Sparkles,
  CheckCircle,
  XCircle,
  Play,
  ArrowRight,
  ShieldCheck,
  Cpu,
  Layers,
  Code,
  Check,
  AlertTriangle,
} from 'lucide-react';

const PRESETS = [
  {
    name: 'Unseen Custom Appliance (Flagship)',
    log: 'SEC-GW-01 2026-08-30T10:32:21Z [BLOCK] proto=TCP src=192.168.10.50:61000 dst=10.20.30.40:80 user=guest',
    description: 'Unknown hardware perimeter gateway with brackets, KV tokens, and custom status',
  },
  {
    name: 'Cisco ASA Firewall Syslog',
    log: '<134>Aug 30 10:32:21 cisco-asa %ASA-4-106023: Deny tcp src inside:192.168.1.5/52100 dst outside:10.10.10.20/443 by access-group "access-group-dmz-01"',
    description: 'Standard Cisco ASA connection teardown / deny syslog with interface zones',
  },
  {
    name: 'Suricata Network-IDS CEF',
    log: 'CEF:0|Suricata|Network-IDS|6.0.4|2001219|ET SCAN Potential SSH Scan|3|src=192.168.1.150 dst=10.10.10.20 spt=49152 dpt=22 proto=TCP act=blocked msg=ET SCAN',
    description: 'ArcSight Common Event Format intrusion detection alert',
  },
  {
    name: 'Palo Alto PAN-OS CSV',
    log: '1,2026/08/30 10:32:21,001801000001,TRAFFIC,drop,1,2026/08/30 10:32:21,192.168.1.105,10.10.10.35,0.0.0.0,0.0.0.0,rule-block-dmz,jdoe,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/08/30 10:32:21,12345,1,54321,80,0,0,0x0,tcp,deny,1200,600,600,10,2026/08/30 10:32:21,0,any,0,123456789,0x0,192.168.0.0-192.168.255.255,10.0.0.0-10.255.255.255,0,5,5,0,0,,0,0,0,0,',
    description: 'Palo Alto Networks 40+ column CSV firewall stream',
  },
  {
    name: 'AWS CloudTrail JSON',
    log: '{"eventVersion":"1.08","userIdentity":{"userName":"security_ops"},"eventTime":"2026-08-30T10:32:21Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","sourceIPAddress":"192.168.1.99"}',
    description: 'Cloud API security audit log in JSON format',
  },
];

export const UnknownLogLab: React.FC = () => {
  const [logInput, setLogInput] = useState(PRESETS[0].log);
  const [inferring, setInferring] = useState(false);
  const [inferenceResult, setInferenceResult] = useState<InferenceResponse | null>(null);

  // Approval Modal State
  const [approvalModalOpen, setApprovalModalOpen] = useState(false);
  const [parserName, setParserName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [version, setVersion] = useState('1.0');
  const [description, setDescription] = useState('');
  const [approving, setApproving] = useState(false);
  const [approvalSuccess, setApprovalSuccess] = useState(false);

  // Follow-up Test Verification State
  const [followUpLog, setFollowUpLog] = useState('');
  const [testingFollowUp, setTestingFollowUp] = useState(false);
  const [followUpResult, setFollowUpResult] = useState<any | null>(null);

  const handleRunInference = async () => {
    if (!logInput.trim()) return;
    setInferring(true);
    setInferenceResult(null);
    setApprovalSuccess(false);
    setFollowUpResult(null);
    try {
      const result = await ApiClient.inferUnknownLog(logInput.trim());
      setInferenceResult(result);
      setParserName(result.suggestedParserName || 'custom_inferred_parser');
      setDisplayName('Custom Inferred Appliance Parser');
      setDescription('Synthesized by Drain-style structural miner + deterministic semantic recognizer');
      // Set default follow-up log sample
      setFollowUpLog(logInput.trim());
    } catch (e: any) {
      console.error(e);
      alert('Inference error: ' + (e.message || 'Failed to infer log structure'));
    } finally {
      setInferring(false);
    }
  };

  const handleApprove = async () => {
    if (!inferenceResult) return;
    setApproving(true);
    try {
      await ApiClient.approveParser({
        parserName,
        displayName,
        version,
        formatType: inferenceResult.suggestedFormat,
        description,
        templatePattern: inferenceResult.minedTemplate,
        regexPattern: inferenceResult.synthesizedRegex,
        fieldMappings: inferenceResult.inferredMappings,
        averageConfidence: inferenceResult.overallConfidence,
        sampleLog: inferenceResult.rawSample,
      });
      setApprovalSuccess(true);
      setApprovalModalOpen(false);
    } catch (e: any) {
      alert('Approval error: ' + e.message);
    } finally {
      setApproving(false);
    }
  };

  const handleRejectToDlq = async () => {
    if (!inferenceResult) return;
    try {
      await ApiClient.ingestSingle(inferenceResult.rawSample, 'LAB_REJECTED_BY_OPERATOR');
      alert('Sample rejected by operator and forwarded to Dead-Letter Queue (DLQ).');
    } catch (e: any) {
      alert('Rejection error: ' + e.message);
    }
  };

  const handleTestLiveFollowUp = async () => {
    if (!followUpLog.trim()) return;
    setTestingFollowUp(true);
    setFollowUpResult(null);
    try {
      const res = await ApiClient.ingestSingle(followUpLog.trim(), 'LAB_VERIFICATION');
      setFollowUpResult(res);
    } catch (e: any) {
      setFollowUpResult({ success: false, errorMessage: e.message });
    } finally {
      setTestingFollowUp(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div>
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
            <FlaskConical size={24} />
          </div>
          <div>
            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
              Unknown Log Lab (Two-Stage Inference)
            </h1>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              Native Java Drain-style template mining + deterministic semantic recognizers + operator approval gate
            </p>
          </div>
        </div>
      </div>

      {/* Preset Selector */}
      <div className="card p-4" style={{ padding: '1.25rem' }}>
        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.65rem' }}>
          Select Realistic Hardware Telemetry Preset:
        </span>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.5rem' }}>
          {PRESETS.map((p, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setLogInput(p.log);
                setInferenceResult(null);
                setApprovalSuccess(false);
                setFollowUpResult(null);
              }}
              className="btn btn-secondary"
              style={{
                fontSize: '0.75rem',
                padding: '0.55rem 0.75rem',
                justifyContent: 'flex-start',
                textAlign: 'left',
                borderColor: logInput === p.log ? 'var(--accent-cyan)' : 'var(--border-color)',
                backgroundColor: logInput === p.log ? 'var(--bg-tertiary)' : 'transparent',
              }}
            >
              <Sparkles size={14} color={logInput === p.log ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
              <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{p.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Raw Sample Input Box */}
      <div className="card p-4" style={{ padding: '1.25rem' }}>
        <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
          Paste Raw Perimeter Log Payload:
        </label>
        <textarea
          rows={3}
          className="input font-mono"
          style={{ width: '100%', resize: 'vertical', fontSize: '0.8125rem' }}
          value={logInput}
          onChange={(e) => setLogInput(e.target.value)}
          placeholder="Paste raw log string here..."
        />

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.85rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Zero cloud dependency • Runs entirely offline inside local JVM
          </span>
          <button
            onClick={handleRunInference}
            disabled={inferring || !logInput.trim()}
            className="btn btn-primary"
            style={{ padding: '0.65rem 1.25rem' }}
          >
            <Sparkles size={16} />
            <span>{inferring ? 'Analyzing Structure...' : 'Execute 2-Stage Inference'}</span>
          </button>
        </div>
      </div>

      {/* Two-Stage Inference Results Display */}
      {inferenceResult && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Top Status & Approval Banner */}
          <div
            className="card"
            style={{
              padding: '1.25rem',
              backgroundColor: 'var(--bg-secondary)',
              borderLeft: `4px solid ${
                inferenceResult.confidenceTier === 'HIGH' ? 'var(--status-success)' : 'var(--status-warning)'
              }`,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <ConfidenceBadge confidence={inferenceResult.overallConfidence} tier={inferenceResult.confidenceTier} size="lg" />
                  <span style={{ fontSize: '1rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                    Inference Complete — {inferenceResult.suggestedFormat} Format Synthesized
                  </span>
                </div>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
                  {inferenceResult.confidenceTier === 'HIGH'
                    ? 'High mapping confidence achieved. Deterministic gate mandates operator confirmation before activation.'
                    : 'Moderate confidence. Please review slot mappings before approving.'}
                </p>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem' }}>
                <button
                  onClick={handleRejectToDlq}
                  className="btn btn-secondary"
                  style={{ color: 'var(--status-danger)' }}
                >
                  <XCircle size={16} />
                  <span>Reject → DLQ</span>
                </button>
                <button
                  onClick={() => setApprovalModalOpen(true)}
                  disabled={approvalSuccess}
                  className="btn btn-primary"
                >
                  <CheckCircle size={16} />
                  <span>{approvalSuccess ? 'Parser Registered (Live!)' : 'Approve & Register Parser'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Stage 1 & Stage 2 Breakdown Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: '1.25rem' }}>
            {/* Stage 1: Structural Template Mining */}
            <div className="card p-4" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <Layers size={18} color="var(--accent-cyan)" />
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Stage 1: Drain Tree Template Mining (Java Native)
                </h3>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                Discovered layout tokens with &lt;*&gt; variable slots partitioned by sequence depth
              </p>

              <div
                style={{
                  backgroundColor: 'var(--bg-code)',
                  padding: '0.85rem',
                  borderRadius: 'var(--radius-md)',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '0.8125rem',
                  color: '#00f0ff',
                  border: '1px solid var(--border-color)',
                  wordBreak: 'break-all',
                }}
              >
                {inferenceResult.minedTemplate}
              </div>

              <div style={{ marginTop: '0.75rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Synthesized Regex Pattern:
                </span>
                <div
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    padding: '0.6rem 0.75rem',
                    borderRadius: 'var(--radius-md)',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '0.75rem',
                    color: 'var(--text-primary)',
                    wordBreak: 'break-all',
                  }}
                >
                  {inferenceResult.synthesizedRegex}
                </div>
              </div>
            </div>

            {/* Stage 2: Deterministic Semantic Recognition Matrix */}
            <div className="card p-4" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <Cpu size={18} color="var(--accent-purple)" />
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Stage 2: Semantic Slot Recognition Matrix
                </h3>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                Type classification (IP, Port, Protocol, Action, User) mapped into canonical OCSF paths
              </p>

              <div style={{ maxHeight: '250px', overflowY: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                      <th style={{ padding: '0.4rem 0.5rem' }}>Slot</th>
                      <th style={{ padding: '0.4rem 0.5rem' }}>Type</th>
                      <th style={{ padding: '0.4rem 0.5rem' }}>Canonical OCSF Path</th>
                      <th style={{ padding: '0.4rem 0.5rem' }}>Sample</th>
                      <th style={{ padding: '0.4rem 0.5rem' }}>Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {inferenceResult.inferredMappings.map((m, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid var(--border-color)' }}>
                        <td style={{ padding: '0.4rem 0.5rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)' }}>
                          {m.slotName}
                        </td>
                        <td style={{ padding: '0.4rem 0.5rem', fontWeight: 600 }}>{m.inferredType}</td>
                        <td style={{ padding: '0.4rem 0.5rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-primary)' }}>
                          {m.canonicalPath}
                        </td>
                        <td style={{ padding: '0.4rem 0.5rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-secondary)' }}>
                          {m.sampleValue}
                        </td>
                        <td style={{ padding: '0.4rem 0.5rem' }}>
                          <ConfidenceBadge confidence={m.confidence} size="sm" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Side-by-Side OCSF Normalized Preview */}
          <div className="card p-4" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
              <Code size={18} color="var(--status-success)" />
              <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                Live Canonical OCSF JSON Preview
              </h3>
            </div>
            <JsonViewer
              data={inferenceResult.previewNormalizedEvent}
              title="Normalized OCSF v1.1.0 Event (Preview)"
              maxHeight="320px"
            />
          </div>

          {/* Live Follow-up Test Box */}
          {approvalSuccess && (
            <div
              className="card"
              style={{
                padding: '1.25rem',
                backgroundColor: 'var(--bg-secondary)',
                border: '1px solid var(--status-success)',
                boxShadow: '0 0 15px rgba(0, 230, 118, 0.15)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <CheckCircle size={20} color="var(--status-success)" />
                <h3 style={{ fontSize: '1.05rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                  Parser Hot-Registered & Active in Memory (Zero-Restart Verification)
                </h3>
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '0.85rem' }}>
                The newly approved parser is now live on the gateway. Send another log from this source to verify automated normalization:
              </p>

              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                <input
                  type="text"
                  className="input font-mono"
                  style={{ flex: 1, minWidth: '280px', fontSize: '0.8125rem' }}
                  value={followUpLog}
                  onChange={(e) => setFollowUpLog(e.target.value)}
                  placeholder="Paste second event from this format..."
                />
                <button
                  onClick={handleTestLiveFollowUp}
                  disabled={testingFollowUp || !followUpLog.trim()}
                  className="btn btn-primary"
                >
                  <Play size={16} />
                  <span>{testingFollowUp ? 'Verifying...' : 'Test Live Parser'}</span>
                </button>
              </div>

              {followUpResult && (
                <div style={{ marginTop: '1rem' }}>
                  {followUpResult.success ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      <div className="badge badge-success" style={{ alignSelf: 'flex-start', padding: '0.4rem 0.75rem' }}>
                        <Check size={14} /> Automatic Live Normalization SUCCESS! (Event ID: {followUpResult.eventId})
                      </div>
                      <JsonViewer
                        data={followUpResult.normalizedEvent}
                        title="Live Normalized OCSF Output"
                        maxHeight="220px"
                      />
                    </div>
                  ) : (
                    <div className="badge badge-danger" style={{ alignSelf: 'flex-start', padding: '0.4rem 0.75rem' }}>
                      <AlertTriangle size={14} /> Normalization Error: {followUpResult.errorMessage}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Operator Approval Modal */}
      <Modal
        isOpen={approvalModalOpen}
        onClose={() => setApprovalModalOpen(false)}
        title="Mandatory Operator Approval Gate — Register Parser"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
            Confirm and register the inferred parser into the live runtime registry. Once approved, the gateway will process subsequent events with zero downtime.
          </p>

          <div>
            <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Parser Identifier (Unique Machine Name)
            </label>
            <input
              type="text"
              className="input font-mono"
              value={parserName}
              onChange={(e) => setParserName(e.target.value)}
              required
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Human Display Name
            </label>
            <input
              type="text"
              className="input"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                Version
              </label>
              <input
                type="text"
                className="input"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                Detected Confidence
              </label>
              <div style={{ paddingTop: '0.4rem' }}>
                <ConfidenceBadge confidence={inferenceResult?.overallConfidence} />
              </div>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Description
            </label>
            <textarea
              rows={2}
              className="input"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.75rem' }}>
            <button
              type="button"
              onClick={() => setApprovalModalOpen(false)}
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleApprove}
              disabled={approving || !parserName.trim()}
              className="btn btn-primary"
            >
              {approving ? 'Registering...' : 'Sign & Hot-Register Parser'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
