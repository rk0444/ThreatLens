import { useState, useRef } from 'react';
import { Search, Shield, AlertTriangle, CheckCircle, HelpCircle, Loader, Globe, FileSearch, Hash, Link, Server, Save } from 'lucide-react';

const API = 'http://127.0.0.1:8000';
const HISTORY_KEY = 'iocHunterHistory';

// Colour and icon by risk; the label is the server's verdict ("Malicious", "Not flagged", "Unknown", ...)
const RISK_CONFIG = {
  high:    { color: '#ff4444', bg: 'rgba(255,68,68,0.12)',   icon: AlertTriangle },
  low:     { color: '#f5a623', bg: 'rgba(245,166,35,0.10)',  icon: AlertTriangle },
  none:    { color: '#48bb78', bg: 'rgba(72,187,120,0.08)',  icon: CheckCircle },
  unknown: { color: '#8BA3BF', bg: 'rgba(139,163,191,0.08)', icon: HelpCircle },
};

const TYPE_ICON = { ip: Server, hash: Hash, url: Link, domain: Globe };

// The EICAR file is a harmless, published antivirus test file that every engine flags on purpose
const EXAMPLE = { label: 'EICAR test file (hash)', value: '44d88612fea8a8f36de82e1278abb02f' };

const loadHistory = () => {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; } catch { return []; }
};

const getJson = async (url, options) => {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = typeof data.detail === 'string' ? data.detail : Array.isArray(data.detail) ? data.detail.map(d => d.msg).join('; ') : null;
    throw new Error(detail || `Lookup failed (HTTP ${res.status})`);
  }
  return data;
};

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
          <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-elevated)', padding: '2px 8px', borderRadius: 4 }}>
            NO RECORD
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
                  color: key === 'is_malicious' ? (val ? '#ff4444' : 'var(--text-primary)')
                       : key === 'malicious'    ? (val > 0 ? '#ff4444' : 'var(--text-primary)')
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
  const [saveState, setSaveState] = useState(null); // null | 'saving' | error text
  const [history, setHistory] = useState(loadHistory);
  const lookupSeq = useRef(0); // only the newest lookup may show its answer

  async function lookup(value) {
    const ioc = (value || input).trim();
    if (!ioc) return;
    const seq = ++lookupSeq.current;

    setLoading(true);
    setError(null);
    setResult(null);
    setSaveState(null);

    try {
      const data = await getJson(`${API}/api/ioc/lookup`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ ioc }),
      });
      if (seq !== lookupSeq.current) return; // a newer lookup started; drop this answer
      setResult(data);
      setHistory(prev => {
        const next = [{ ioc, verdict: data.verdict, risk: data.risk, type: data.type },
                      ...prev.filter(h => h.ioc !== ioc)].slice(0, 10);
        try { localStorage.setItem(HISTORY_KEY, JSON.stringify(next)); } catch { /* storage unavailable */ }
        return next;
      });
    } catch (e) {
      if (seq === lookupSeq.current) setError(e.message);
    } finally {
      if (seq === lookupSeq.current) setLoading(false);
    }
  }

  async function saveToOsint() {
    setSaveState('saving');
    try {
      await getJson(`${API}/api/ioc/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ioc: result.ioc, summary: result.tags.join('; ') }),
      });
      setResult(r => ({ ...r, saved: true }));
      setSaveState(null);
    } catch (e) {
      setSaveState(`Could not save (${e.message})`);
    }
  }

  const risk     = result ? (RISK_CONFIG[result.risk] || RISK_CONFIG.unknown) : null;
  const TypeIcon = result ? (TYPE_ICON[result.type] || Shield) : null;
  const sources  = result?.sources || {};

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
          Paste an IP address (IPv4 or IPv6), file hash (MD5/SHA1/SHA256), URL, or domain. IPs are checked against
          published blocklists and AbuseIPDB; hashes, URLs and domains against VirusTotal.
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
          onKeyDown={e => e.key === 'Enter' && !loading && lookup()}
          placeholder="IP address, file hash, URL or domain"
          aria-label="IP address, file hash, URL or domain"
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

      {/* Example */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 28 }}>
        <span style={{ fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center' }}>Try:</span>
        <button
          onClick={() => { setInput(EXAMPLE.value); lookup(EXAMPLE.value); }}
          style={{
            background: 'var(--bg-elevated)', border: '1px solid var(--border)',
            borderRadius: 6, padding: '4px 12px', fontSize: 12,
            color: 'var(--text-secondary)', cursor: 'pointer',
          }}
        >
          {EXAMPLE.label}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div role="alert" style={{
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
            display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap',
          }}>
            <risk.icon size={40} color={risk.color} />
            <div style={{ flex: 1, minWidth: 200 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
                <span style={{ fontSize: 22, fontWeight: 800, color: risk.color }}>
                  {result.verdict.toUpperCase()}
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
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
                {result.verdict === 'Not flagged' && `No detections from ${result.checked_by.join(' and ')}.`}
                {result.verdict === 'Reported' && `Reported on AbuseIPDB below its malicious threshold.`}
                {result.verdict === 'Unknown' && (result.checked_by?.length
                  ? `Not on the ${result.checked_by.join(' or ')}; no other source could answer, so it is not known to be safe.`
                  : 'No reputation source had data on it, so it is not known to be safe.')}
                {result.verdict === 'Not checked' && sources.note?.message}
                {result.verdict === 'Flagged' && 'VirusTotal reports per-engine detections; weigh how many engines agree.'}
              </div>
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

          {/* Save a malicious finding as an OSINT alert, only when the analyst asks */}
          {['Malicious', 'Flagged'].includes(result.verdict) && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              {result.saved ? (
                <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>Saved to OSINT alerts.</span>
              ) : (
                <button
                  onClick={saveToOsint}
                  disabled={saveState === 'saving'}
                  style={{
                    background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6,
                    padding: '6px 14px', fontSize: 13, color: 'var(--text-primary)', cursor: 'pointer',
                    display: 'flex', alignItems: 'center', gap: 6,
                  }}
                >
                  <Save size={14} /> {saveState === 'saving' ? 'Saving...' : 'Save to OSINT alerts'}
                </button>
              )}
              {saveState && saveState !== 'saving' && <span role="alert" style={{ fontSize: 13, color: '#ff6b6b' }}>{saveState}</span>}
            </div>
          )}

          {/* Source cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
            {sources.blocklist && (
              <SourceCard
                title="PUBLISHED BLOCKLISTS"
                icon={Shield}
                data={sources.blocklist}
                color={sources.blocklist.found ? '#ff4444' : 'var(--border)'}
              />
            )}
            {sources.abuseipdb && (
              <SourceCard
                title="ABUSEIPDB"
                icon={Shield}
                data={sources.abuseipdb}
                color={sources.abuseipdb.is_malicious ? '#ff4444' : 'var(--border)'}
              />
            )}
            {sources.virustotal && (
              <SourceCard
                title="VIRUSTOTAL"
                icon={FileSearch}
                data={sources.virustotal}
                color={sources.virustotal.malicious > 0 ? '#ff4444' : 'var(--border)'}
              />
            )}
          </div>
        </div>
      )}

      {/* History (kept in this browser) */}
      {history.length > 0 && (
        <div style={{ marginTop: 36 }}>
          <h3 style={{ fontSize: 13, color: 'var(--text-muted)', letterSpacing: 1, marginBottom: 12 }}>
            RECENT LOOKUPS
          </h3>
          <div style={{ display: 'grid', gap: 6 }}>
            {history.map(h => {
              const hRisk = RISK_CONFIG[h.risk] || RISK_CONFIG.unknown;
              const HTypeIcon = TYPE_ICON[h.type] || Shield;
              return (
                <button
                  key={h.ioc}
                  onClick={() => { setInput(h.ioc); lookup(h.ioc); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12, width: '100%', textAlign: 'left',
                    background: 'var(--bg-card)', border: '1px solid var(--border)',
                    borderRadius: 8, padding: '10px 14px', cursor: 'pointer', color: 'inherit',
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
                    {(h.verdict || '').toUpperCase()}
                  </span>
                </button>
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
