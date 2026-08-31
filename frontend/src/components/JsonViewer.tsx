import React, { useState } from 'react';
import { Copy, Check, ChevronRight, ChevronDown } from 'lucide-react';

interface JsonViewerProps {
  data: any;
  title?: string;
  maxHeight?: string;
  defaultExpanded?: boolean;
}

export const JsonViewer: React.FC<JsonViewerProps> = ({
  data,
  title,
  maxHeight = '400px',
  defaultExpanded = true,
}) => {
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(defaultExpanded);

  const jsonString = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const renderFormattedJson = (json: string) => {
    // Simple colored syntax highlighting
    const highlighted = json
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(
        /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
        (match) => {
          let cls = 'color: #9cdcfe;'; // number/default
          if (/^"/.test(match)) {
            if (/:$/.test(match)) {
              cls = 'color: #00f0ff; font-weight: 600;'; // key
            } else {
              cls = 'color: #ce9178;'; // string
            }
          } else if (/true|false/.test(match)) {
            cls = 'color: #569cd6; font-weight: bold;'; // boolean
          } else if (/null/.test(match)) {
            cls = 'color: #569cd6; font-style: italic;'; // null
          }
          return `<span style="${cls}">${match}</span>`;
        }
      );

    return <pre dangerouslySetInnerHTML={{ __html: highlighted }} style={{ margin: 0, fontSize: '0.8125rem', lineHeight: '1.45', fontFamily: 'JetBrains Mono, monospace' }} />;
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--bg-code)',
        border: '1px solid var(--border-color)',
        borderRadius: 'var(--radius-md)',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '0.5rem 0.85rem',
          backgroundColor: 'rgba(255, 255, 255, 0.03)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
        }}
      >
        <button
          onClick={() => setExpanded(!expanded)}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--text-primary)',
            fontSize: '0.75rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '0.35rem',
            cursor: 'pointer',
          }}
        >
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          <span>{title || 'JSON Payload'}</span>
        </button>
        <button
          onClick={handleCopy}
          className="btn btn-ghost"
          style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem', height: '24px' }}
          title="Copy JSON"
        >
          {copied ? <Check size={12} color="var(--status-success)" /> : <Copy size={12} />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
      {expanded && (
        <div
          style={{
            padding: '0.85rem',
            maxHeight,
            overflowY: 'auto',
            color: '#d4d4d4',
          }}
        >
          {renderFormattedJson(jsonString)}
        </div>
      )}
    </div>
  );
};
