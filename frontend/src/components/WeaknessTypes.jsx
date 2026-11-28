// Top 20 CVEs by risk (within the page's filters) grouped by the weakness types (CWE) NVD publishes for them.
// Same data as /api/cves/graph; shown as groups so every label stays readable.
import { useEffect, useMemo, useState } from 'react';
import { EmptyState, ErrorState, Skeleton } from './ui';

const API = 'http://127.0.0.1:8000';
const NO_CWE = 'No CWE published';

export default function WeaknessTypes({ filterQuery = '', highlightedCve, onSelectCve }) {
  const [result, setResult] = useState({ query: null, data: null, error: null });
  const [retry, setRetry] = useState(0);

  useEffect(() => {
    let alive = true;
    fetch(`${API}/api/cves/graph?${filterQuery}`)
      .then(res => (res.ok ? res.json() : Promise.reject(new Error(`HTTP ${res.status}`))))
      .then(data => { if (alive) setResult({ query: filterQuery, data, error: null }); })
      .catch(e => { if (alive) setResult({ query: filterQuery, data: null, error: e.message }); });
    return () => { alive = false; };
  }, [filterQuery, retry]);

  const groups = useMemo(() => {
    const nodes = result.data?.nodes || [];
    const cves = new Map(nodes.filter(n => n.type === 'cve').map(n => [n.id, n]));
    const byCwe = new Map();
    const linked = new Set();
    for (const link of result.data?.links || []) {
      const source = typeof link.source === 'object' ? link.source.id : link.source;
      const target = typeof link.target === 'object' ? link.target.id : link.target;
      if (!cves.has(source)) continue;
      linked.add(source);
      if (!byCwe.has(target)) byCwe.set(target, []);
      byCwe.get(target).push(cves.get(source));
    }
    const unlinked = [...cves.values()].filter(c => !linked.has(c.id));
    const list = [...byCwe.entries()].map(([cwe, items]) => ({ cwe, items: items.sort((a, b) => (b.risk ?? 0) - (a.risk ?? 0)) }));
    list.sort((a, b) => b.items.length - a.items.length || a.cwe.localeCompare(b.cwe, undefined, { numeric: true }));
    if (unlinked.length) list.push({ cwe: NO_CWE, items: unlinked });
    return { list, cveCount: cves.size };
  }, [result.data]);

  // Bring the focused CVE into view once its group is on screen
  useEffect(() => {
    if (highlightedCve) document.querySelector(`[data-cve="${CSS.escape(highlightedCve)}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [highlightedCve, groups]);

  if (result.error) return <ErrorState onRetry={() => setRetry(r => r + 1)}>Could not load weakness types ({result.error}).</ErrorState>;
  if (result.query !== filterQuery) return <div style={{ padding: 'var(--s4)' }}><Skeleton lines={6} /></div>;
  if (groups.cveCount === 0) return <EmptyState title="No CVEs match these filters" />;

  const focusShown = highlightedCve && groups.list.some(g => g.items.some(c => c.id === highlightedCve));

  return (
    <div>
      {highlightedCve && !focusShown && (
        <p className="muted small" style={{ padding: 'var(--s3) var(--s4) 0' }}>
          {highlightedCve} is not among the top {groups.cveCount} CVEs shown here with the current filters.
        </p>
      )}
      <ul className="cwe-groups">
        {groups.list.map(group => (
          <li key={group.cwe} className="cwe-group">
            <div className="cwe-name">
              {group.cwe === NO_CWE ? <span className="muted">{NO_CWE}</span> : (
                <a className="mono" href={`https://cwe.mitre.org/data/definitions/${group.cwe.replace('CWE-', '')}.html`} target="_blank" rel="noreferrer">
                  {group.cwe}
                </a>
              )}
              <span className="muted small">{group.items.length} CVE{group.items.length === 1 ? '' : 's'}</span>
            </div>
            <div className="cwe-cves">
              {group.items.map(c => (
                <button key={c.id} type="button" data-cve={c.id}
                  className={`cve-chip mono${c.id === highlightedCve ? ' is-focused' : ''}`}
                  aria-pressed={c.id === highlightedCve || undefined}
                  title={`Risk ${c.risk != null ? Number(c.risk).toFixed(1) : '–'}${c.kev ? ' · CISA KEV' : ''}`}
                  onClick={() => onSelectCve?.(c.id)}>
                  {c.id}{c.kev && <span className="cve-chip-tag">KEV</span>}
                </button>
              ))}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
