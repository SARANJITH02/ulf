import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { RuleItem } from '../api/types';
import {
  Sliders,
  Save,
  CheckCircle,
  Shield,
  Zap,
  RotateCcw,
  Lock,
  Sparkles,
} from 'lucide-react';

export const RulesConfig: React.FC = () => {
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  // Form states
  const [confHigh, setConfHigh] = useState('0.90');
  const [confMed, setConfMed] = useState('0.70');
  const [enrichRfc, setEnrichRfc] = useState(true);
  const [enrichMitre, setEnrichMitre] = useState(true);
  const [dlqRetries, setDlqRetries] = useState('3');
  const [requireApproval, setRequireApproval] = useState(true);

  const fetchRules = async () => {
    setLoading(true);
    try {
      const data = await ApiClient.getRules();
      setRules(data);

      data.forEach((r) => {
        if (r.ruleKey === 'CONFIDENCE_HIGH_THRESHOLD') setConfHigh(r.ruleValue);
        if (r.ruleKey === 'CONFIDENCE_MEDIUM_THRESHOLD') setConfMed(r.ruleValue);
        if (r.ruleKey === 'ENRICHMENT_RFC1918_ENABLED') setEnrichRfc(r.ruleValue === 'true' && r.enabled);
        if (r.ruleKey === 'ENRICHMENT_MITRE_ENABLED') setEnrichMitre(r.ruleValue === 'true' && r.enabled);
        if (r.ruleKey === 'DLQ_MAX_RETRIES') setDlqRetries(r.ruleValue);
        if (r.ruleKey === 'REQUIRE_OPERATOR_APPROVAL') setRequireApproval(r.ruleValue === 'true' && r.enabled);
      });
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleSaveAll = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSaveMessage(null);

    try {
      await ApiClient.updateRule('CONFIDENCE_HIGH_THRESHOLD', confHigh, true);
      await ApiClient.updateRule('CONFIDENCE_MEDIUM_THRESHOLD', confMed, true);
      await ApiClient.updateRule('ENRICHMENT_RFC1918_ENABLED', String(enrichRfc), enrichRfc);
      await ApiClient.updateRule('ENRICHMENT_MITRE_ENABLED', String(enrichMitre), enrichMitre);
      await ApiClient.updateRule('DLQ_MAX_RETRIES', dlqRetries, true);
      await ApiClient.updateRule('REQUIRE_OPERATOR_APPROVAL', String(requireApproval), requireApproval);

      setSaveMessage('All operator rules updated and applied live into JVM memory cache with zero restart!');
      setTimeout(() => setSaveMessage(null), 4000);
      fetchRules();
    } catch (err: any) {
      alert('Error updating rules: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxWidth: '850px' }}>
      {/* Header */}
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
          <Sliders size={24} />
        </div>
        <div>
          <h1 style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
            Operator Rules & Pipeline Policies
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            Configure runtime thresholds, offline enrichment toggles, and human-in-the-loop policies
          </p>
        </div>
      </div>

      {saveMessage && (
        <div
          style={{
            padding: '0.85rem 1rem',
            backgroundColor: 'var(--status-success-bg)',
            color: 'var(--status-success)',
            border: '1px solid rgba(0, 230, 118, 0.4)',
            borderRadius: 'var(--radius-md)',
            fontSize: '0.8125rem',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <CheckCircle size={18} />
          <span>{saveMessage}</span>
        </div>
      )}

      <form onSubmit={handleSaveAll} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {/* Confidence Thresholds */}
        <div className="card p-4" style={{ padding: '1.25rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Sparkles size={18} color="var(--accent-cyan)" />
            Inference Confidence Thresholds
          </h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Cutoff values for categorizing automatically inferred field mappings into confidence tiers
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                <span style={{ color: 'var(--text-primary)' }}>High Confidence Cutoff (≥ {Math.round(parseFloat(confHigh) * 100)}%)</span>
                <span style={{ color: 'var(--status-success)', fontFamily: 'JetBrains Mono, monospace' }}>{confHigh}</span>
              </div>
              <input
                type="range"
                min="0.75"
                max="0.99"
                step="0.01"
                value={confHigh}
                onChange={(e) => setConfHigh(e.target.value)}
                style={{ width: '100%', accentColor: 'var(--accent-cyan)' }}
              />
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                Inferred parsers scoring at or above this threshold are marked recommended for human operator sign-off.
              </span>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                <span style={{ color: 'var(--text-primary)' }}>Medium / Low Confidence Split (≥ {Math.round(parseFloat(confMed) * 100)}%)</span>
                <span style={{ color: 'var(--status-warning)', fontFamily: 'JetBrains Mono, monospace' }}>{confMed}</span>
              </div>
              <input
                type="range"
                min="0.50"
                max="0.85"
                step="0.01"
                value={confMed}
                onChange={(e) => setConfMed(e.target.value)}
                style={{ width: '100%', accentColor: 'var(--status-warning)' }}
              />
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                Events falling below this threshold are routed to DLQ or inspection queue.
              </span>
            </div>
          </div>
        </div>

        {/* Offline Enrichment Toggles */}
        <div className="card p-4" style={{ padding: '1.25rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Zap size={18} color="var(--accent-purple)" />
            Air-Gapped Offline Enrichment Modules
          </h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Enable or disable zero-cloud offline telemetry augmentations
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={enrichRfc}
                onChange={(e) => setEnrichRfc(e.target.checked)}
                style={{ width: '18px', height: '18px', marginTop: '0.15rem', accentColor: 'var(--accent-cyan)' }}
              />
              <div>
                <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)', display: 'block' }}>
                  RFC 1918 Private/Public IP Classification
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  Evaluates source and destination IPs locally against 10/8, 172.16/12, and 192.168/16 subnet masks to set <code>isInternal</code>.
                </span>
              </div>
            </label>

            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={enrichMitre}
                onChange={(e) => setEnrichMitre(e.target.checked)}
                style={{ width: '18px', height: '18px', marginTop: '0.15rem', accentColor: 'var(--accent-cyan)' }}
              />
              <div>
                <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)', display: 'block' }}>
                  Heuristic MITRE ATT&CK Technique Tagging
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  Matches event signatures against local rule dictionary (e.g. repeated SSH/RDP blocks → T1110 Brute Force, sweeps → T1046 Discovery).
                </span>
              </div>
            </label>
          </div>
        </div>

        {/* DLQ & Approval Policies */}
        <div className="card p-4" style={{ padding: '1.25rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Lock size={18} color="var(--status-success)" />
            Gateway Governance & Approval Gate
          </h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Non-negotiable security controls and retry limits
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
                Maximum Automated DLQ Retry Limit
              </label>
              <input
                type="number"
                min="1"
                max="10"
                className="input"
                style={{ width: '120px' }}
                value={dlqRetries}
                onChange={(e) => setDlqRetries(e.target.value)}
              />
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.25rem' }}>
                Maximum retry count before an event is marked permanently escalated.
              </span>
            </div>

            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={requireApproval}
                onChange={(e) => setRequireApproval(e.target.checked)}
                style={{ width: '18px', height: '18px', marginTop: '0.15rem', accentColor: 'var(--accent-cyan)' }}
              />
              <div>
                <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)', display: 'block' }}>
                  Mandatory Human Operator Approval Gate
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  Guarantees that inferred parsers are never self-authorized or auto-deployed without explicit operator click in the Unknown Log Lab.
                </span>
              </div>
            </label>
          </div>
        </div>

        {/* Save Button */}
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button
            type="submit"
            disabled={saving}
            className="btn btn-primary"
            style={{ padding: '0.7rem 1.75rem', fontSize: '0.875rem' }}
          >
            <Save size={16} />
            <span>{saving ? 'Applying Policies...' : 'Save & Apply Live to Pipeline'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
