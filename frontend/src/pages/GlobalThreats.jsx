import { useState, useEffect, useCallback } from 'react';
import { RotateCw } from 'lucide-react';
import WeaknessTypes from '../components/WeaknessTypes';
import CveDrawer from '../components/CveDrawer';
import CustomDropdown from '../components/CustomDropdown';
import { PageHeader, Button, Badge, Card, Table, Tabs } from '../components/ui';
import { useWebSocket } from '../hooks/useWebSocket';

const API = 'http://127.0.0.1:8000';
const PAGE = 50;

const SORT_OPTIONS = [
  { value: 'Severity', label: 'Risk score' },
  { value: 'EPSS %', label: 'EPSS probability' },
  { value: 'Published Date', label: 'Published date' },
  { value: 'CVSS Score', label: 'CVSS score' },
];
const SORT_PARAM = { 'Severity': 'risk_score', 'EPSS %': 'epss', 'Published Date': 'published', 'CVSS Score': 'cvss' };

const SEVERITY_OPTIONS = [
  { value: 'All Severities', label: 'All severities' },
  { value: 'Critical', label: 'Critical' },
  { value: 'High', label: 'High' },
  { value: 'Medium', label: 'Medium' },
  { value: 'Low', label: 'Low' },
];

const EPSS_OPTIONS = [0, 0.5, 0.7, 0.9, 0.95, 0.99].map(v => ({ value: String(v), label: v === 0 ? 'Any EPSS' : `EPSS percentile ≥ ${Math.round(v * 100)}` }));

const readAssetFilter = () => {
  try { return localStorage.getItem('assetAwareFilter') === 'true'; } catch { return false; }
};

const formatDate = (value) => (value ? new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '–');

const formatProducts = (products) => {
  if (!Array.isArray(products) || products.length === 0) return <span className="muted">Not listed</span>;
  const text = products.length <= 2 ? products.join(', ') : `${products[0]}, ${products[1]} +${products.length - 2}`;
  return <span title={products.join(', ')}>{text}</span>;
};

const COLUMNS = [
  { key: 'risk_band', header: 'Severity', width: 104, render: c => (c.risk_band ? <Badge severity={c.risk_band} /> : <span className="muted">–</span>) },
  { key: 'risk_score', header: 'Risk', align: 'right', mono: true, width: 56, render: c => Number(c.risk_score ?? 0).toFixed(1) },
  {
    key: 'cve_id', header: 'CVE', truncate: true, render: c => (
      <div className="cve-cell">
        <span className="mono">{c.cve_id}</span>
        <span className="cve-cell-desc" title={c.description}>{c.description}</span>
      </div>
    ),
  },
  { key: 'cvss_score', header: 'CVSS', align: 'right', mono: true, width: 56, render: c => (c.cvss_score != null ? Number(c.cvss_score).toFixed(1) : <span className="muted" title="NVD has not scored this CVE yet">–</span>) },
  {
    key: 'epss_score', header: 'EPSS', align: 'right', mono: true, width: 104, render: c => (c.epss_score == null
      ? <span className="muted" title="EPSS has not scored this CVE yet">–</span>
      : <>{(c.epss_score * 100).toFixed(1)}%{c.epss_percentile != null && <span className="muted small"> p{Math.round(c.epss_percentile * 100)}</span>}</>),
  },
  {
    key: 'exploited', header: 'Exploited', width: 120, render: c => (c.cisa_kev
      ? <Badge title="On CISA's Known Exploited Vulnerabilities list">{c.ransomware_use ? 'KEV · ransomware' : 'KEV'}</Badge>
      : c.actively_exploited
        ? <span className="small" title="NVD links a public exploit; no confirmed exploitation in the wild">Public exploit</span>
        : <span className="muted">–</span>),
  },
  { key: 'affected_products', header: 'Products', width: 160, truncate: true, render: c => formatProducts(c.affected_products) },
  { key: 'published_date', header: 'Published', mono: true, width: 104, render: c => formatDate(c.published_date) },
];

const GlobalThreats = () => {
  const [cves, setCves] = useState([]);
  const [selectedCve, setSelectedCve] = useState(null);
  const [focusCve, setFocusCve] = useState(null);
  const [view, setView] = useState('cves');
  const [loaded, setLoaded] = useState({ query: null, error: null });
  const [lastUpdated, setLastUpdated] = useState(null);
  const [openError, setOpenError] = useState(null);
  const [limit, setLimit] = useState(PAGE);
  const [filters, setFilters] = useState({ severity: 'All Severities', epssMin: '0', myAssetsOnly: readAssetFilter(), sortBy: 'Severity' });

  // Filters shared with the weakness view; the table adds sort and paging. The server picks which CVEs to send.
  const filterParams = new URLSearchParams();
  if (filters.myAssetsOnly) filterParams.append('affected_only', 'true');
  if (filters.severity !== 'All Severities') filterParams.append('band', filters.severity);
  if (Number(filters.epssMin) > 0) filterParams.append('epss_pct_min', filters.epssMin);
  const filterQuery = filterParams.toString();
  const cveQuery = `${filterQuery}&sort=${SORT_PARAM[filters.sortBy]}&limit=${limit}`;
  // Loading until the rows for the current query have arrived (a live refresh keeps the rows visible)
  const loading = loaded.query !== cveQuery;

  const load = useCallback(() => {
    fetch(`${API}/api/cves?${cveQuery}`)
      .then(res => (res.ok ? res.json() : Promise.reject(new Error(`HTTP ${res.status}`))))
      .then(data => {
        setCves(Array.isArray(data) ? data : (data.cves || []));
        setLastUpdated(new Date());
        setLoaded({ query: cveQuery, error: null });
      })
      .catch(e => setLoaded({ query: cveQuery, error: e.message }));
  }, [cveQuery]);

  useEffect(() => { load(); }, [load]);

  // New CVEs were ingested: refetch so they go through the same filters and sort
  useWebSocket(useCallback(msg => { if (msg.type === 'CVES_UPDATED') load(); }, [load]));

  const setFilter = (key, value) => { setFilters(f => ({ ...f, [key]: value })); setLimit(PAGE); };

  const openCveById = (cveId) => {
    setOpenError(null);
    fetch(`${API}/api/cves/${encodeURIComponent(cveId)}`)
      .then(res => (res.ok ? res.json() : Promise.reject(new Error(`HTTP ${res.status}`))))
      .then(setSelectedCve)
      .catch(e => setOpenError(`Could not open ${cveId} (${e.message}).`));
  };

  const emptyText = filters.myAssetsOnly
    ? 'Matching compares the products NVD lists for each CVE with the software your endpoints report.'
    : filters.severity === 'Critical'
      ? "Critical means a CVE on CISA's KEV list that affects one of your assets."
      : 'Try a lower EPSS percentile or another severity.';

  return (
    <div className="page-container page-stack">
      <PageHeader
        title="Global Threats"
        description="Published CVEs from NVD, scored with EPSS and CISA KEV. Filters apply to both views."
        actions={<>
          {lastUpdated && <span className="muted small">Updated {lastUpdated.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</span>}
          <Button size="sm" icon={RotateCw} onClick={load}>Refresh</Button>
        </>}
      />

      <div className="toolbar" role="group" aria-label="Filters">
        <CustomDropdown label="Sort by" options={SORT_OPTIONS} value={filters.sortBy} onChange={v => setFilter('sortBy', v)} />
        <CustomDropdown label="Severity" hideLabel options={SEVERITY_OPTIONS} value={filters.severity} onChange={v => setFilter('severity', v)} />
        <CustomDropdown label="Minimum EPSS percentile" hideLabel options={EPSS_OPTIONS} value={filters.epssMin} onChange={v => setFilter('epssMin', v)} />
        <label className="checkbox">
          <input type="checkbox" checked={filters.myAssetsOnly}
            onChange={e => {
              const val = e.target.checked;
              setFilter('myAssetsOnly', val);
              try { localStorage.setItem('assetAwareFilter', val); } catch { /* preference not kept */ }
            }} />
          Only CVEs affecting my endpoints
        </label>
      </div>

      <Card flush>
        <div style={{ padding: '0 var(--s4)' }}>
          <Tabs label="View" value={view} onChange={setView} tabs={[
            { id: 'cves', label: 'CVEs', count: loading ? null : `${cves.length}${cves.length >= limit ? '+' : ''}` },
            { id: 'cwe', label: 'Weakness types' },
          ]} />
        </div>
        {view === 'cves' ? (
          <>
            <Table
              caption="CVEs matching the filters"
              columns={COLUMNS}
              rows={cves}
              loading={loading && cves.length === 0}
              error={loaded.error && cves.length === 0 ? `The backend did not answer (${loaded.error}).` : null}
              onRetry={load}
              onRowClick={setSelectedCve}
              selectedKey={selectedCve?.id}
              emptyTitle="No CVEs match these filters"
              emptyText={emptyText}
              skeletonRows={10}
              maxHeight="calc(100vh - 290px)"
            />
            {loaded.error && cves.length > 0 && <div role="alert" className="inline-error">The latest refresh failed ({loaded.error}). Showing the last loaded rows.</div>}
            {!loading && !loaded.error && cves.length >= limit && (
              <div style={{ padding: 'var(--s3) var(--s4)', borderTop: '1px solid var(--border)' }}>
                <Button size="sm" onClick={() => setLimit(limit + PAGE)}>Load {PAGE} more</Button>
              </div>
            )}
          </>
        ) : (
          <>
            <p className="muted small" style={{ padding: 'var(--s3) var(--s4) 0' }}>
              The 20 highest-risk CVEs matching the filters, grouped by the weakness types (CWE) NVD lists for them. Select a CVE for details.
            </p>
            <WeaknessTypes filterQuery={filterQuery} highlightedCve={focusCve} onSelectCve={id => { setFocusCve(id); openCveById(id); }} />
          </>
        )}
        {openError && <div role="alert" className="inline-error">{openError}</div>}
      </Card>

      <CveDrawer
        cve={selectedCve}
        onClose={() => setSelectedCve(null)}
        footer={view === 'cves' && selectedCve && (
          <Button onClick={() => { setFocusCve(selectedCve.cve_id); setSelectedCve(null); setView('cwe'); }}>
            Show its weakness type
          </Button>
        )}
      />
    </div>
  );
};

export default GlobalThreats;
