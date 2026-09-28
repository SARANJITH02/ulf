import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { MerkleBatch } from '../api/types';
import { Modal } from '../components/Modal';
import {
  ShieldCheck,
  Download,
  Eye,
  RefreshCw,
  Clock,
  Layers,
  FileCheck2,
  Copy,
  Check,
  AlertTriangle,
  FileCode,
  Lock,
} from 'lucide-react';

export const AuditLedger: React.FC = () => {
  const [batches, setBatches] = useState<MerkleBatch[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState(false);
  const [selectedBatch, setSelectedBatch] = useState<MerkleBatch | null>(null);
  const [batchDetails, setBatchDetails] = useState<any | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [copiedRoot, setCopiedRoot] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  const currentUser = ApiClient.getCurrentUser();
  const isAdmin = currentUser?.role === 'ADMIN';

  const fetchBatches = async () => {
    try {
      setLoading(true);
      const data = await ApiClient.listMerkleBatches();
      setBatches(data);
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to load Merkle batches: ' + err.message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBatches();
  }, []);

  const handleTriggerBatch = async () => {
    try {
      setTriggering(true);
      setStatusMsg(null);
      const res = await ApiClient.triggerMerkleBatch();
      if ('status' in res && res.status === 'NO_EVENTS') {
        setStatusMsg({ type: 'info', text: res.message });
      } else {
        setStatusMsg({ type: 'success', text: `Successfully published new Merkle Batch ${(res as MerkleBatch).id}` });
        await fetchBatches();
      }
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to trigger batch: ' + err.message });
    } finally {
      setTriggering(false);
    }
  };

  const handleInspectBatch = async (batch: MerkleBatch) => {
    setSelectedBatch(batch);
    setLoadingDetails(true);
    try {
      const bundle = await ApiClient.exportMerkleBatch(batch.id);
      setBatchDetails(bundle);
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to export batch details: ' + err.message });
    } finally {
      setLoadingDetails(false);
    }
  };

  const handleDownloadBundle = (batchId: string, bundleData?: any) => {
    const dataToDownload = bundleData || batchDetails;
    if (!dataToDownload) return;
    const blob = new Blob([JSON.stringify(dataToDownload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `merkle-audit-batch-${batchId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRoot(id);
    setTimeout(() => setCopiedRoot(null), 2000);
  };

  const totalEvents = batches.reduce((sum, b) => sum + (b.eventCount || 0), 0);

  return (
    <div className="container" style={{ padding: '2rem 1.5rem', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '2rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
            <h1 style={{ margin: 0, fontSize: '1.75rem', fontWeight: 800, color: 'var(--text-primary)' }}>
              Merkle-Batched Cryptographic Audit Ledger
            </h1>
            <span className="badge badge-success" style={{ fontSize: '0.75rem' }}>
              <Lock size={12} /> NON-REPUDIATION
            </span>
            <span className="badge badge-info" style={{ fontSize: '0.75rem' }}>
              <FileCheck2 size={12} /> APPEND-ONLY JSONL
            </span>
          </div>
          <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.875rem', maxWidth: '800px' }}>
            Periodic cryptographic batching of raw log SHA-256 digests into binary Merkle trees. Generates durable chain-of-custody proofs and standalone exportable audit packages for compliance authorities.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button
            onClick={fetchBatches}
            className="btn btn-secondary"
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <RefreshCw size={16} className={loading ? 'spin' : ''} /> Refresh
          </button>
          {isAdmin && (
            <button
              onClick={handleTriggerBatch}
              className="btn btn-primary"
              disabled={triggering}
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            >
              <ShieldCheck size={16} />
              {triggering ? 'Computing Tree...' : 'Trigger Merkle Batch'}
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

      {/* KPI Stats Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
            Published Merkle Batches
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>
            {batches.length}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Hourly cron + on-demand triggers
          </div>
        </div>

        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
            Batched Raw Events
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--status-success)' }}>
            {totalEvents.toLocaleString()}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Cryptographically sealed with SHA-256
          </div>
        </div>

        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
            Durable Ledger Store
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace' }}>
            merkle-ledger.jsonl
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', marginTop: '0.25rem' }}>
            Append-only file storage active
          </div>
        </div>

        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
            Proof Verification Standard
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            RFC 6962 Binary Merkle
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            O(log N) inclusion proofs
          </div>
        </div>
      </div>

      {/* Batches Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--text-primary)' }}>
            Published Merkle Batches (Chronological Ledger)
          </div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            {batches.length} published batch{batches.length === 1 ? '' : 'es'}
          </span>
        </div>

        {loading ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <RefreshCw size={24} className="spin" style={{ margin: '0 auto 1rem' }} />
            <div>Loading cryptographic audit ledger...</div>
          </div>
        ) : batches.length === 0 ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <Layers size={36} style={{ margin: '0 auto 1rem', opacity: 0.5 }} />
            <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>No Merkle Batches Created Yet</div>
            <p style={{ fontSize: '0.875rem', maxWidth: '500px', margin: '0 auto 1.5rem' }}>
              Raw log events are automatically batched every hour. You can also trigger an immediate batch using the button above.
            </p>
            {isAdmin && (
              <button onClick={handleTriggerBatch} className="btn btn-primary">
                Create First Batch Now
              </button>
            )}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Batch Identifier</th>
                  <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Time Range (UTC)</th>
                  <th style={{ textAlign: 'center', padding: '0.875rem 1rem' }}>Event Count</th>
                  <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Merkle Root Hash (SHA-256)</th>
                  <th style={{ textAlign: 'left', padding: '0.875rem 1rem' }}>Published At</th>
                  <th style={{ textAlign: 'right', padding: '0.875rem 1rem' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {batches.map((batch) => (
                  <tr key={batch.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <td style={{ padding: '0.875rem 1rem' }}>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, fontSize: '0.8125rem', color: 'var(--accent-cyan)' }}>
                        {batch.id}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        Batch #{batch.batchNumber || 1}
                      </div>
                    </td>
                    <td style={{ padding: '0.875rem 1rem', fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                      <div>{new Date(batch.periodStart).toISOString().replace('T', ' ').substring(0, 19)}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        to {new Date(batch.periodEnd).toISOString().replace('T', ' ').substring(0, 19)}
                      </div>
                    </td>
                    <td style={{ padding: '0.875rem 1rem', textAlign: 'center' }}>
                      <span className="badge badge-info" style={{ fontWeight: 700 }}>
                        {batch.eventCount} events
                      </span>
                    </td>
                    <td style={{ padding: '0.875rem 1rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', color: 'var(--text-primary)', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {batch.merkleRoot}
                        </span>
                        <button
                          onClick={() => copyToClipboard(batch.merkleRoot, batch.id)}
                          className="btn btn-ghost"
                          style={{ padding: '0.2rem', color: copiedRoot === batch.id ? 'var(--status-success)' : 'var(--text-muted)' }}
                          title="Copy Merkle Root"
                        >
                          {copiedRoot === batch.id ? <Check size={14} /> : <Copy size={14} />}
                        </button>
                      </div>
                    </td>
                    <td style={{ padding: '0.875rem 1rem', fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                      {new Date(batch.createdAt).toISOString().replace('T', ' ').substring(0, 19)}
                    </td>
                    <td style={{ padding: '0.875rem 1rem', textAlign: 'right' }}>
                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                        <button
                          onClick={() => handleInspectBatch(batch)}
                          className="btn btn-secondary"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                        >
                          <Eye size={14} /> Inspect
                        </button>
                        <button
                          onClick={async () => {
                            const b = await ApiClient.exportMerkleBatch(batch.id);
                            handleDownloadBundle(batch.id, b);
                          }}
                          className="btn btn-primary"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                        >
                          <Download size={14} /> Export
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Batch Details Modal */}
      {selectedBatch && (
        <Modal
          isOpen={true}
          onClose={() => {
            setSelectedBatch(null);
            setBatchDetails(null);
          }}
          title={`Merkle Batch Inspection — ${selectedBatch.id}`}
        >
          {loadingDetails ? (
            <div style={{ padding: '2rem', textAlign: 'center' }}>
              <RefreshCw size={24} className="spin" style={{ margin: '0 auto 1rem' }} />
              <div>Loading batch leaves and cryptographic tree...</div>
            </div>
          ) : batchDetails ? (
            <div>
              {/* Batch Metadata Header */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem', marginBottom: '1.25rem', backgroundColor: 'var(--bg-tertiary)', padding: '1rem', borderRadius: 'var(--radius-md)' }}>
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Merkle Root Hash</div>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>
                    {batchDetails.merkleRoot}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Tree Integrity Status</div>
                  <div style={{ color: batchDetails.verifiedRootMatchesTree ? 'var(--status-success)' : 'var(--status-danger)', fontWeight: 700, fontSize: '0.85rem' }}>
                    {batchDetails.verifiedRootMatchesTree ? '✓ ROOT VERIFIED MATCH' : '✗ MISMATCH DETECTED'}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Leaf Event Count</div>
                  <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
                    {batchDetails.eventCount} events
                  </div>
                </div>
              </div>

              {/* Leaves Table */}
              <div style={{ marginBottom: '1.25rem' }}>
                <div style={{ fontWeight: 700, fontSize: '0.875rem', marginBottom: '0.5rem', color: 'var(--text-primary)' }}>
                  Deterministic Leaf Order (Tree Ingestion Order)
                </div>
                <div style={{ maxHeight: '300px', overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)' }}>
                  <table className="table" style={{ width: '100%', fontSize: '0.8rem' }}>
                    <thead>
                      <tr>
                        <th style={{ padding: '0.5rem' }}>Index</th>
                        <th style={{ padding: '0.5rem' }}>Raw Event ID</th>
                        <th style={{ padding: '0.5rem' }}>Event ID</th>
                        <th style={{ padding: '0.5rem' }}>Leaf Hash (SHA-256)</th>
                      </tr>
                    </thead>
                    <tbody>
                      {batchDetails.leafEvents?.map((leaf: any) => (
                        <tr key={leaf.leafIndex} style={{ borderBottom: '1px solid var(--border-color)' }}>
                          <td style={{ padding: '0.5rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>#{leaf.leafIndex}</td>
                          <td style={{ padding: '0.5rem', fontFamily: 'JetBrains Mono, monospace' }}>{leaf.rawEventId}</td>
                          <td style={{ padding: '0.5rem', fontFamily: 'JetBrains Mono, monospace' }}>{leaf.eventId || '—'}</td>
                          <td style={{ padding: '0.5rem', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                            {leaf.rawHashSha256}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                <button
                  onClick={() => handleDownloadBundle(selectedBatch.id)}
                  className="btn btn-primary"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                >
                  <Download size={16} /> Download Signed Audit Package (.json)
                </button>
              </div>
            </div>
          ) : (
            <div>Failed to load batch bundle.</div>
          )}
        </Modal>
      )}
    </div>
  );
};
