import { useState, useEffect, useRef, useMemo } from 'react';
import { Search, X, ExternalLink } from 'lucide-react';
import { PageHeader, Button, Card, Table, Input, Modal, ErrorState, Skeleton } from '../components/ui';

const API = 'http://127.0.0.1:8000';

// Marks the search text inside a value (escaped, so "(" or "+" in the search can't break the RegExp)
const Highlight = ({ text = '', term }) => {
  if (!term.trim()) return text;
  const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return text.split(new RegExp(`(${escaped})`, 'gi')).map((part, i) =>
    part.toLowerCase() === term.toLowerCase() ? <mark key={i}>{part}</mark> : part);
};

const getJson = (url) => fetch(url).then(res => {
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
});

// MITRE lists the group's own name as its first alias
const otherAliases = (group) => (group.aliases || []).filter(a => a !== group.name);

const SORTERS = {
  name: (a, b) => a.name.localeCompare(b.name),
  mitre_id: (a, b) => (a.mitre_id || '').localeCompare(b.mitre_id || '', undefined, { numeric: true }),
  technique_count: (a, b) => (a.technique_count ?? 0) - (b.technique_count ?? 0),
};

const ThreatActors = () => {
  const [actors, setActors]     = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [retry, setRetry]       = useState(0);
  const [term, setTerm]         = useState('');
  const [sort, setSort]         = useState({ key: 'name', dir: 'asc' });
  const [detail, setDetail]     = useState(null); // { id, data?, error? }
  const searchRef = useRef(null);

  useEffect(() => {
    let alive = true;
    getJson(`${API}/api/threat-actors`)
      .then(data => { if (alive) { setActors(data); setError(null); } })
      .catch(err => { if (alive) setError(err.message); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [retry]);

  // "/" focuses the search, as in many analyst tools
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const openActor = (actor) => {
    setDetail({ id: actor.id, name: actor.name });
    getJson(`${API}/api/threat-actors/${actor.id}`)
      .then(data => setDetail(d => (d?.id === actor.id ? { ...d, data } : d)))
      .catch(err => setDetail(d => (d?.id === actor.id ? { ...d, error: err.message } : d)));
  };

  const rows = useMemo(() => {
    const t = term.trim().toLowerCase();
    const list = !t ? actors : actors.filter(a =>
      a.name.toLowerCase().includes(t) ||
      (a.aliases || []).join(' ').toLowerCase().includes(t) ||
      (a.mitre_id || '').toLowerCase().includes(t));
    const sorted = [...list].sort(SORTERS[sort.key]);
    return sort.dir === 'desc' ? sorted.reverse() : sorted;
  }, [actors, term, sort]);

  const onSort = (key) => setSort(s => ({ key, dir: s.key === key && s.dir === 'asc' ? 'desc' : key === 'technique_count' ? 'desc' : 'asc' }));

  const group = detail?.data?.group;
  const techniques = detail?.data?.techniques || [];

  return (
    <div className="page-container page-stack">
      <PageHeader
        title="Threat Actors"
        description={`Groups published in MITRE ATT&CK${actors.length ? ` (${actors.length})` : ''}, synced at startup and weekly. Select a group for its techniques.`}
      />

      <div className="toolbar">
        <Input
          ref={searchRef} label="Search threat actors" hideLabel icon={Search} className="search-field"
          value={term} onChange={e => setTerm(e.target.value)}
          onKeyDown={e => { if (e.key === 'Escape') setTerm(''); }}
          placeholder="Name, alias or MITRE ID   ( / )" autoComplete="off" spellCheck={false}
        />
        {term && <Button variant="ghost" size="sm" icon={X} onClick={() => setTerm('')}>Clear</Button>}
        {term && <span className="small muted" role="status">{rows.length} of {actors.length} groups</span>}
      </div>

      <Card flush>
        <Table
          caption="MITRE ATT&CK groups"
          rows={rows}
          loading={loading}
          error={error && `Could not load threat actors (${error}). Is the backend running?`}
          onRetry={() => { setLoading(true); setRetry(r => r + 1); }}
          onRowClick={openActor}
          selectedKey={detail?.id}
          sort={sort}
          onSort={onSort}
          skeletonRows={12}
          maxHeight="calc(100vh - 250px)"
          emptyTitle={term ? `No groups match "${term}"` : 'No MITRE ATT&CK data yet'}
          emptyText={term ? 'Search by name, alias or MITRE ID.' : 'Groups appear after the MITRE sync, which runs at startup and weekly.'}
          columns={[
            { key: 'name', header: 'Group', sortable: true, width: 220, render: a => <strong><Highlight text={a.name} term={term} /></strong> },
            { key: 'mitre_id', header: 'MITRE ID', sortable: true, mono: true, width: 100, render: a => <Highlight text={a.mitre_id || ''} term={term} /> },
            { key: 'aliases', header: 'Also known as', truncate: true, render: a => {
              const aliases = otherAliases(a);
              return aliases.length ? <span className="muted" title={aliases.join(', ')}><Highlight text={aliases.join(', ')} term={term} /></span> : <span className="muted">–</span>;
            } },
            { key: 'technique_count', header: 'Techniques', sortable: true, align: 'right', mono: true, width: 120, render: a => a.technique_count ?? 0 },
          ]}
        />
      </Card>

      <Modal
        drawer
        open={Boolean(detail)}
        onClose={() => setDetail(null)}
        title={detail && (
          <span style={{ display: 'grid', gap: 2 }}>
            <span>{group?.name || detail.name}</span>
            <span className="small muted mono" style={{ fontWeight: 400 }}>{group?.mitre_id}</span>
          </span>
        )}
      >
        {detail?.error ? (
          <ErrorState title="Could not load this group">{detail.error}</ErrorState>
        ) : !group ? <Skeleton lines={6} /> : (
          <div className="stack">
            <dl className="facts">
              <div><dt>Origin</dt><dd className="fact-text">{group.country || <span className="muted">Not published by MITRE</span>}</dd></div>
              <div><dt>Motivation</dt><dd className="fact-text">{group.motivation || <span className="muted">Not published by MITRE</span>}</dd></div>
            </dl>
            <section>
              <h3 className="section-title">Description</h3>
              <p>{group.description || 'MITRE publishes no description for this group.'}</p>
            </section>
            {otherAliases(group).length > 0 && (
              <section>
                <h3 className="section-title">Also known as</h3>
                <p>{otherAliases(group).join(', ')}</p>
              </section>
            )}
            <section>
              <h3 className="section-title">ATT&CK techniques ({techniques.length})</h3>
              {techniques.length === 0 ? <p className="muted">MITRE lists no techniques for this group.</p> : (
                <Table
                  caption="Techniques used by this group"
                  rows={techniques}
                  rowKey="technique_id"
                  columns={[
                    { key: 'technique_id', header: 'ID', mono: true, width: 96, render: t => (
                      <a href={`https://attack.mitre.org/techniques/${t.technique_id.replace('.', '/')}/`} target="_blank" rel="noreferrer">{t.technique_id}</a>
                    ) },
                    { key: 'name', header: 'Technique', truncate: true, render: t => <span title={t.name}>{t.name}</span> },
                    { key: 'tactic', header: 'Tactic', width: 140, truncate: true, render: t => <span className="muted" title={t.tactic}>{t.tactic || '–'}</span> },
                  ]}
                />
              )}
            </section>
            <a href={`https://attack.mitre.org/groups/${group.mitre_id}/`} target="_blank" rel="noreferrer"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--s1)', width: 'fit-content' }}>
              View on MITRE ATT&CK <ExternalLink size={14} aria-hidden="true" />
            </a>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default ThreatActors;
