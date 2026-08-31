import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { NormalizedEventRecord } from '../api/types';
import { JsonViewer } from '../components/JsonViewer';
import {
  Share2,
  Copy,
  Download,
  Check,
  Search,
  Layers,
  FileCode,
} from 'lucide-react';

export const SiemExporter: React.FC = () => {
  const [events, setEvents] = useState<NormalizedEventRecord[]>([]);
  const [selectedEventId, setSelectedEventId] = useState<string>('');
  const [exportFormat, setExportFormat] = useState<'CEF' | 'LEEF' | 'ECS'>('CEF');
  const [exportedOutput, setExportedOutput] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    ApiClient.getRecentEvents().then((data) => {
      setEvents(data);
      if (data.length > 0 && !selectedEventId) {
        setSelectedEventId(data[0].eventId);
      }
    }).catch(() => {});
  }, []);

  const runExport = async () => {
    if (!selectedEventId) return;
    setLoading(true);
    try {
      if (exportFormat === 'CEF') {
        const res = await ApiClient.exportCef(selectedEventId);
        setExportedOutput(res.wireFormat);
      } else if (exportFormat === 'LEEF') {
        const res = await ApiClient.exportLeef(selectedEventId);
        setExportedOutput(res.wireFormat);
      } else if (exportFormat === 'ECS') {
        const res = await ApiClient.exportEcs(selectedEventId);
        setExportedOutput(JSON.stringify(res, null, 2));
      }
    } catch (e: any) {
      setExportedOutput('Export error: ' + e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedEventId) {
      runExport();
    }
  }, [selectedEventId, exportFormat]);

  const handleCopy = () => {
    navigator.clipboard.writeText(exportedOutput);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const ext = exportFormat === 'ECS' ? 'json' : 'log';
    const blob = new Blob([exportedOutput], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ulpf_export_${selectedEventId.substring(0, 12)}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
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
          <Share2 size={24} />
        </div>
        <div>
          <h1 style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
            Multi-SIEM Exporter & Wire Format Translator
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            Reverse-translate canonical OCSF telemetry into ArcSight CEF, IBM QRadar LEEF, or Elastic ECS JSON
          </p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem' }}>
        {/* Source Selector */}
        <div className="card p-4" style={{ padding: '1.25rem' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Layers size={16} color="var(--accent-cyan)" />
            Select Source Normalized Event
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '420px', overflowY: 'auto' }}>
            {events.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                No events currently in database. Inject sample from Dashboard first.
              </div>
            ) : (
              events.map((evt) => (
                <div
                  key={evt.eventId}
                  onClick={() => setSelectedEventId(evt.eventId)}
                  style={{
                    padding: '0.75rem',
                    borderRadius: 'var(--radius-md)',
                    border: `1px solid ${selectedEventId === evt.eventId ? 'var(--accent-cyan)' : 'var(--border-color)'}`,
                    backgroundColor: selectedEventId === evt.eventId ? 'var(--bg-tertiary)' : 'transparent',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                  className="card-interactive"
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                      {evt.eventId.substring(0, 18)}...
                    </span>
                    <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>{evt.format}</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-primary)', display: 'flex', justifyContent: 'space-between' }}>
                    <span>{evt.sourceIp || 'unknown'} → {evt.destinationIp || 'unknown'}</span>
                    <span style={{ fontWeight: 600, color: evt.action === 'blocked' ? 'var(--status-danger)' : 'var(--status-success)' }}>
                      {evt.action}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Translation Output Panel */}
        <div className="card p-4" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FileCode size={16} color="var(--accent-purple)" />
              Target Wire Format Translation
            </h3>

            {/* Target Format Tabs */}
            <div style={{ display: 'flex', backgroundColor: 'var(--bg-tertiary)', padding: '0.2rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
              {(['CEF', 'LEEF', 'ECS'] as const).map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => setExportFormat(fmt)}
                  className={`btn ${exportFormat === fmt ? 'btn-primary' : 'btn-ghost'}`}
                  style={{ fontSize: '0.75rem', padding: '0.3rem 0.75rem' }}
                >
                  {fmt}
                </button>
              ))}
            </div>
          </div>

          {/* Code Viewer Panel */}
          <div
            style={{
              flex: 1,
              minHeight: '280px',
              backgroundColor: 'var(--bg-code)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              padding: '1rem',
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: '0.8125rem',
              color: '#00f0ff',
              overflowY: 'auto',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
              lineHeight: '1.5',
            }}
          >
            {loading ? 'Translating to target format...' : exportedOutput || 'Select an event on the left to export.'}
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
            <button
              onClick={handleCopy}
              disabled={!exportedOutput || loading}
              className="btn btn-secondary"
              style={{ fontSize: '0.8125rem' }}
            >
              {copied ? <Check size={14} color="var(--status-success)" /> : <Copy size={14} />}
              <span>{copied ? 'Copied' : 'Copy Payload'}</span>
            </button>
            <button
              onClick={handleDownload}
              disabled={!exportedOutput || loading}
              className="btn btn-primary"
              style={{ fontSize: '0.8125rem' }}
            >
              <Download size={14} />
              <span>Download File</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
