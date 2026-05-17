import { useState } from 'react';
import { Search, Shield, AlertTriangle, CheckCircle, XCircle, Loader, Database, Globe, FileSearch, Hash, Link, Server } from 'lucide-react';

const API = 'http://127.0.0.1:8000';

const RISK_CONFIG = {
  critical: { color: '#ff2d2d', bg: 'rgba(255,45,45,0.12)',  label: 'CRITICAL',   icon: XCircle },
  high:     { color: '#ff6b35', bg: 'rgba(255,107,53,0.12)', label: 'HIGH',        icon: AlertTriangle },
  medium:   { color: '#f5a623', bg: 'rgba(245,166,35,0.12)', label: 'SUSPICIOUS',  icon: AlertTriangle },
  low:      { color: '#f5a623', bg: 'rgba(245,166,35,0.08)', label: 'LOW RISK',    icon: Shield },
  none:     { color: '#00ff88', bg: 'rgba(0,255,136,0.08)',  label: 'CLEAN',       icon: CheckCircle },
};

const TYPE_ICON = {
  ip:      Server,
  hash:    Hash,
  url:     Link,
  domain:  Globe,
};

const EXAMPLES = [
  { label: 'Suspicious IP',   value: '185.220.101.34' },
  { label: 'Malware Hash',    value: '44d88612fea8a8f36de82e1278abb02f' },
  { label: 'Phishing URL',    value: 'http://malware-test.com/payload' },
  { label: 'Bad Domain',      value: 'evil-c2-domain.ru' },
];

function SourceCard({ title, icon: Icon, data, color }) {
  if (!data) return null;
  const hasError = data.error;

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${hasError ? 'var(--border)' : color || 'var(--border)'}`,
      borderRadius: 10,
      padding: '16px 20px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <Icon size={18} color={hasError ? 'var(--text-muted)' : color || 'var(--accent-gold)'} />
        <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)', letterSpacing: 1 }}>
          {title}
        </span>
        {hasError && (
          <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-elevated)', padding: '2px 8px', borderRadius: 4 }}>
            UNAVAILABLE
          </span>
        )}
        {!hasError && data.found === false && (
          <span style={{ marginLeft: 'auto', fontSize: 11, color: '#00ff88', background: 'rgba(0,255,136,0.08)', padding: '2px 8px', borderRadius: 4 }}>
            NOT FOUND
          </span>
        )}
      </div>

      {hasError ? (
        <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>{data.error}</p>
      ) : (
        <div style={{ display: 'grid', gap: 6 }}>
          {Object.entries(data)
            .filter(([k]) => !['error', 'found'].includes(k))
            .map(([key, val]) => (
              <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'capitalize' }}>
                  {key.replace(/_/g, ' ')}
                </span>
                <span style={{
                  fontSize: 12,
                  color: key === 'is_malicious' ? (val ? '#ff4444' : '#00ff88')
                       : key === 'verdict'      ? (val === 'Malicious' ? '#ff4444' : '#00ff88')
                       : key === 'malicious'    ? (val > 0 ? '#ff4444' : '#00ff88')
                       : key === 'score'        ? (val > 75 ? '#ff4444' : val > 25 ? '#f5a623' : '#00ff88')
                       : 'var(--text-primary)',
                  fontWeight: 500,
                  textAlign: 'right',
                  maxWidth: 220,
                  wordBreak: 'break-all',
                }}>
                  {typeof val === 'boolean' ? (val ? 'Yes' : 'No') : String(val ?? '—')}
                </span>
              </div>
            ))}
        </div>
      )}
    </div>
  );
}

export default function IOCHunter() {
  const [input, setInput]     = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState(null);
  const [history, setHistory] = useState([]);

  async function lookup(value) {
    const ioc = (value || input).trim();
    if (!ioc) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const resp = await fetch(`${API}/api/ioc/lookup`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ ioc }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || 'Lookup failed');
      setResult(data);
      setHistory(prev => [{ ioc, verdict: data.verdict, risk: data.risk, type: data.type }, ...prev].slice(0, 10));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  const risk    = result ? (RISK_CONFIG[result.risk] || RISK_CONFIG.none) : null;
  const TypeIcon = result ? (TYPE_ICON[result.type] || Shield) : null;

  return (
    <div style={{ padding: '28px 32px', maxWidth: 960, margin: '0 auto' }}>

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 6 }}>
          <FileSearch size={28} color="var(--accent-gold)" />
          <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            IOC Hunter
          </h1>
        </div>
        <p style={{ color: 'var(--text-muted)', fontSize: 14, margin: 0 }}>
          Paste an IP address, file hash (MD5/SHA1/SHA256), URL, or domain — cross-referenced against AbuseIPDB, VirusTotal, and local OSINT intelligence.
        </p>
      </div>

      {/* Search bar */}
      <div style={{
        display: 'flex', gap: 10, marginBottom: 16,
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 10, padding: '6px 6px 6px 16px',
      }}>
        <Search size={18} color="var(--text-muted)" style={{ alignSelf: 'center', flexShrink: 0 }} />
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && lookup()}
          placeholder="185.220.101.34 · 44d88612fea8a8f36de82e1278abb02f · https://evil.com · malware.ru"
          style={{
            flex: 1, background: 'none', border: 'none', outline: 'none',
            color: 'var(--text-primary)', fontSize: 14, fontFamily: 'monospace',
          }}
        />
        <button
          onClick={() => lookup()}
          disabled={loading || !input.trim()}
          style={{
            background: loading ? 'var(--bg-elevated)' : 'var(--accent-gold)',
            color: loading ? 'var(--text-muted)' : '#000',
            border: 'none', borderRadius: 7, padding: '10px 22px',
            fontWeight: 700, fontSize: 13, cursor: loading ? 'not-allowed' : 'pointer',
            display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0,
          }}
        >
          {loading ? <><Loader size={14} className="spin" /> Analyzing...</> : 'Analyze'}
        </button>
      </div>

      {/* Example pills */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 28 }}>
        <span style={{ fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center' }}>Try:</span>
        {EXAMPLES.map(ex => (
          <button
            key={ex.value}
            onClick={() => { setInput(ex.value); lookup(ex.value); }}
            style={{
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '4px 12px', fontSize: 12,
              color: 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            {ex.label}
          </button>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div style={{
          background: 'rgba(255,45,45,0.08)', border: '1px solid rgba(255,45,45,0.3)',
          borderRadius: 8, padding: '12px 16px', marginBottom: 20,
          color: '#ff6b6b', fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {/* Results */}
      {result && risk && (
        <div style={{ display: 'grid', gap: 16 }}>

          {/* Verdict banner */}
          <div style={{
            background: risk.bg,
            border: `1px solid ${risk.color}`,
            borderRadius: 12, padding: '20px 24px',
            display: 'flex', alignItems: 'center', gap: 20,
          }}>
            <risk.icon size={40} color={risk.color} />
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
                <span style={{ fontSize: 22, fontWeight: 800, color: risk.color }}>
                  {risk.label}
                </span>
                <span style={{
                  background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                  borderRadius: 5, padding: '2px 10px', fontSize: 11,
                  color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 5,
                }}>
                  {TypeIcon && <TypeIcon size={11} />}
                  {result.type.toUpperCase()}
                </span>
              </div>
              <code style={{ fontSize: 13, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                {result.ioc}
              </code>
            </div>
            {result.tags?.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5, alignItems: 'flex-end' }}>
                {result.tags.map(tag => (
                  <span key={tag} style={{
                    background: 'var(--bg-elevated)', border: `1px solid ${risk.color}40`,
                    borderRadius: 5, padding: '3px 10px', fontSize: 11, color: risk.color,
                    whiteSpace: 'nowrap',
                  }}>
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Source cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
            <SourceCard
              title="LOCAL OSINT DB"
              icon={Database}
              data={result.sources.osint_db}
              color={result.sources.osint_db?.found ? '#f5a623' : '#00ff88'}
            />
            {result.sources.abuseipdb && (
              <SourceCard
                title="ABUSEIPDB"
                icon={Shield}
                data={result.sources.abuseipdb}
                color={result.sources.abuseipdb?.is_malicious ? '#ff4444' : '#00ff88'}
              />
            )}
            {result.sources.virustotal && (
              <SourceCard
                title="VIRUSTOTAL"
                icon={FileSearch}
                data={result.sources.virustotal}
                color={result.sources.virustotal?.malicious > 0 ? '#ff4444' : '#00ff88'}
              />
            )}
          </div>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div style={{ marginTop: 36 }}>
          <h3 style={{ fontSize: 13, color: 'var(--text-muted)', letterSpacing: 1, marginBottom: 12 }}>
            RECENT LOOKUPS
          </h3>
          <div style={{ display: 'grid', gap: 6 }}>
            {history.map((h, i) => {
              const hRisk = RISK_CONFIG[h.risk] || RISK_CONFIG.none;
              const HTypeIcon = TYPE_ICON[h.type] || Shield;
              return (
                <div
                  key={i}
                  onClick={() => { setInput(h.ioc); lookup(h.ioc); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    background: 'var(--bg-card)', border: '1px solid var(--border)',
                    borderRadius: 8, padding: '10px 14px', cursor: 'pointer',
                  }}
                >
                  <HTypeIcon size={14} color="var(--text-muted)" />
                  <code style={{ flex: 1, fontSize: 12, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                    {h.ioc}
                  </code>
                  <span style={{
                    fontSize: 11, fontWeight: 700, color: hRisk.color,
                    background: hRisk.bg, padding: '2px 10px', borderRadius: 4,
                    flexShrink: 0,
                  }}>
                    {hRisk.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <style>{`
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}