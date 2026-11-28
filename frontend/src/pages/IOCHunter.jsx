import { useState, useRef } from 'react';
import { Search, Save, Loader2, Server, Hash, Link, Globe, Shield } from 'lucide-react';
import { PageHeader, Button, Badge, Card, Table, Input, ErrorState, EmptyState, Skeleton } from '../components/ui';

const API = 'http://127.0.0.1:8000';
const HISTORY_KEY = 'iocHunterHistory';

// The server's risk picks the badge; its verdict ("Malicious", "Not flagged", "Unknown", ...) is the label
const verdictBadge = (risk, verdict) => {
  if (risk === 'high') return <Badge severity="high">{verdict}</Badge>;
  if (risk === 'low') return <Badge severity="medium">{verdict}</Badge>;
  if (risk === 'none') return <Badge tone="ok">{verdict}</Badge>;
  return <Badge severity="info">{verdict || 'Unknown'}</Badge>;
};

const TYPE_ICON = { ip: Server, hash: Hash, url: Link, domain: Globe };
const TYPE_LABEL = { ip: 'IP address', hash: 'File hash', url: 'URL', domain: 'Domain' };

// The EICAR file is a harmless, published antivirus test file that every engine flags on purpose
const EXAMPLE = { label: 'EICAR test file hash', value: '44d88612fea8a8f36de82e1278abb02f' };

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

const formatValue = (val) => (typeof val === 'boolean' ? (val ? 'Yes' : 'No') : String(val ?? '–'));

// One reputation source: its status in the header, its published fields as label/value rows
function SourceCard({ title, data, flagged }) {
  if (!data) return null;
  const status = data.error ? <Badge>Unavailable</Badge>
    : data.found === false ? <Badge>No record</Badge>
    : flagged ? <Badge severity="high">Flagged</Badge>
    : <Badge tone="ok">Not flagged</Badge>;
  return (
    <Card title={title} actions={status}>
      {data.error ? <p className="muted">{data.error}</p> : (
        <dl className="kv">
          {Object.entries(data).filter(([k]) => !['error', 'found'].includes(k)).map(([key, val]) => (
            <div key={key}>
              <dt>{key.replace(/_/g, ' ')}</dt>
              <dd>{formatValue(val)}</dd>
            </div>
          ))}
        </dl>
      )}
    </Card>
  );
}

const explain = (result, sources) => {
  switch (result.verdict) {
    case 'Not flagged': return `No detections from ${result.checked_by.join(' and ')}.`;
    case 'Reported': return 'Reported on AbuseIPDB, below its malicious threshold.';
    case 'Unknown': return result.checked_by?.length
      ? `Not on the ${result.checked_by.join(' or ')}; no other source could answer, so it is not known to be safe.`
      : 'No reputation source had data on it, so it is not known to be safe.';
    case 'Not checked': return sources.note?.message;
    case 'Flagged': return 'VirusTotal reports per-engine detections; weigh how many engines agree.';
    default: return null;
  }
};

export default function IOCHunter() {
  const [input, setInput]     = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState(null);
  const [saveState, setSaveState] = useState(null); // null | 'saving' | error text
  const [history, setHistory] = useState(loadHistory);
  const lookupSeq = useRef(0); // only the newest lookup may show its answer

  async function lookup(value) {
    const ioc = (value ?? input).trim();
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

  const lookupValue = (value) => { setInput(value); lookup(value); };

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
      setSaveState(`Could not save (${e.message}).`);
    }
  }

  const sources  = result?.sources || {};
  const TypeIcon = result ? (TYPE_ICON[result.type] || Shield) : null;
  const canSave  = result && ['Malicious', 'Flagged'].includes(result.verdict);

  return (
    <div className="page-container page-stack">
      <PageHeader
        title="IOC Hunter"
        description="Check an IP address (IPv4 or IPv6), file hash (MD5, SHA-1, SHA-256), URL or domain. IPs are checked against published blocklists and AbuseIPDB; hashes, URLs and domains against VirusTotal."
      />

      <Card>
        <form className="ioc-form" onSubmit={e => { e.preventDefault(); if (!loading) lookup(); }}>
          <Input
            label="Indicator" hideLabel icon={Search} className="ioc-input"
            value={input} onChange={e => setInput(e.target.value)}
            placeholder="IP address, file hash, URL or domain"
            autoComplete="off" spellCheck={false}
          />
          <Button type="submit" variant="primary" icon={loading ? Loader2 : undefined}
            className={loading ? 'is-busy' : undefined} disabled={loading || !input.trim()}>
            {loading ? 'Checking…' : 'Check'}
          </Button>
        </form>
        <div className="small muted" style={{ marginTop: 'var(--s2)', display: 'flex', alignItems: 'center', gap: 'var(--s2)', flexWrap: 'wrap' }}>
          Try a harmless test value:
          <Button size="sm" variant="ghost" onClick={() => lookupValue(EXAMPLE.value)}>{EXAMPLE.label}</Button>
        </div>
      </Card>

      {error && <Card flush><ErrorState title="Lookup failed">{error}</ErrorState></Card>}

      {loading && (
        <Card aria-busy="true"><Skeleton width="40%" height={20} /><div style={{ marginTop: 'var(--s3)' }}><Skeleton lines={3} /></div></Card>
      )}

      {result && (
        <>
          <Card>
            <div className="verdict">
              <div className="verdict-main">
                <div className="verdict-line">
                  {verdictBadge(result.risk, result.verdict)}
                  <Badge>{TypeIcon && <TypeIcon size={12} aria-hidden="true" />}{TYPE_LABEL[result.type] || result.type}</Badge>
                </div>
                <h2 className="mono verdict-ioc">{result.ioc}</h2>
                {explain(result, sources) && <p className="muted">{explain(result, sources)}</p>}
                {result.tags?.length > 0 && (
                  <div style={{ display: 'flex', gap: 'var(--s1)', flexWrap: 'wrap', marginTop: 'var(--s2)' }}>
                    {result.tags.map(tag => <Badge key={tag}>{tag}</Badge>)}
                  </div>
                )}
              </div>
              {canSave && (
                <div className="verdict-actions">
                  {result.saved ? <span className="small muted">Saved to OSINT alerts.</span> : (
                    <Button icon={saveState === 'saving' ? Loader2 : Save} className={saveState === 'saving' ? 'is-busy' : undefined}
                      onClick={saveToOsint} disabled={saveState === 'saving'}>
                      {saveState === 'saving' ? 'Saving…' : 'Save to OSINT alerts'}
                    </Button>
                  )}
                  {saveState && saveState !== 'saving' && <span role="alert" className="small">{saveState}</span>}
                </div>
              )}
            </div>
          </Card>

          <div className="grid-fill">
            {sources.blocklist && <SourceCard title="Published blocklists" data={sources.blocklist} flagged={Boolean(sources.blocklist.found)} />}
            {sources.abuseipdb && <SourceCard title="AbuseIPDB" data={sources.abuseipdb} flagged={Boolean(sources.abuseipdb.is_malicious)} />}
            {sources.virustotal && <SourceCard title="VirusTotal" data={sources.virustotal} flagged={sources.virustotal.malicious > 0} />}
          </div>
        </>
      )}

      <Card title="Recent lookups" subtitle="The last 10 lookups, kept on this computer. Select one to check it again." flush>
        {history.length === 0 ? (
          <EmptyState title="No lookups yet">Indicators you check appear here.</EmptyState>
        ) : (
          <Table
            caption="Recent lookups"
            rows={history}
            rowKey="ioc"
            onRowClick={h => lookupValue(h.ioc)}
            columns={[
              { key: 'verdict', header: 'Verdict', width: 140, render: h => verdictBadge(h.risk, h.verdict) },
              { key: 'type', header: 'Type', width: 110, render: h => TYPE_LABEL[h.type] || h.type || '–' },
              { key: 'ioc', header: 'Indicator', mono: true, truncate: true, render: h => <span title={h.ioc}>{h.ioc}</span> },
            ]}
          />
        )}
      </Card>
    </div>
  );
}
