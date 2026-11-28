import { useState, useEffect, useCallback } from 'react';
import { RotateCw, Sparkles, Loader2 } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import CveDrawer from '../components/CveDrawer';
import { PageHeader, Button, Badge, Card, KpiStrip, Table, EmptyState, ErrorState, Skeleton } from '../components/ui';
import { severityKey } from '../utils/riskScore';

const API = 'http://127.0.0.1:8000';

// Server events after which the overview numbers may have changed
const REFRESH_EVENTS = ['CVES_UPDATED', 'NEW_INCIDENT', 'INCIDENT_UPDATE', 'MORNING_BRIEF_GENERATED', 'ASSET_ADDED', 'ASSET_DELETED'];

const formatTimeAgo = (timestamp, now) => {
  const mins = Math.floor((now - new Date(timestamp).getTime()) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
};

const formatTime = (date) => date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });

const THREAT_COLUMNS = [
  { key: 'risk_band', header: 'Severity', width: 104, render: t => (t.risk_band ? <Badge severity={t.risk_band} /> : <span style={{ color: 'var(--text-3)' }}>–</span>) },
  { key: 'cve_id', header: 'CVE', mono: true, width: 150 },
  { key: 'description', header: 'Description', truncate: true, render: t => <span title={t.description}>{t.description}</span> },
  { key: 'cisa_kev', header: 'KEV', width: 56, render: t => (t.cisa_kev ? <Badge title="Listed in the CISA Known Exploited Vulnerabilities catalog">KEV</Badge> : null) },
  { key: 'cvss_score', header: 'CVSS', align: 'right', mono: true, width: 64, render: t => (t.cvss_score != null ? Number(t.cvss_score).toFixed(1) : '–') },
  { key: 'epss_score', header: 'EPSS', align: 'right', mono: true, width: 72, render: t => (t.epss_score != null ? `${(Number(t.epss_score) * 100).toFixed(1)}%` : '–') },
  { key: 'risk_score', header: 'Risk', align: 'right', mono: true, width: 64, render: t => Number(t.risk_score).toFixed(1) },
];

// Risk bands of today's CVEs: four labelled rows, values printed, bar length relative to the largest band
const BandBars = ({ bands }) => {
  const max = Math.max(...bands.map(b => b.value), 1);
  return (
    <ul className="band-bars">
      {bands.map(b => {
        const key = severityKey(b.name);
        return (
          <li key={b.name}>
            <Badge severity={b.name} />
            <span className="band-track" aria-hidden="true">
              <span className="band-fill" style={{ width: `${(b.value / max) * 100}%`, background: key ? `var(--sev-${key})` : 'var(--text-3)' }} />
            </span>
            <span className="band-value mono">{b.value}</span>
          </li>
        );
      })}
    </ul>
  );
};

const Overview = () => {
  const [overview, setOverview] = useState(null);
  const [error, setError] = useState(null);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [briefStatus, setBriefStatus] = useState(null); // null | 'generating' | error text
  const [selectedCve, setSelectedCve] = useState(null);
  const [threatError, setThreatError] = useState(null);
  const [now, setNow] = useState(() => Date.now());

  // Keep "x m ago" labels current while the page stays open
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60000);
    return () => clearInterval(t);
  }, []);

  const fetchOverviewData = useCallback(() => {
    fetch(`${API}/api/overview`)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => { setOverview(data); setError(null); setUpdatedAt(new Date()); })
      .catch(e => setError(e.message));
  }, []);

  useEffect(() => { fetchOverviewData(); }, [fetchOverviewData]);

  // Nothing loaded yet (e.g. backend still starting): keep trying until it answers
  useEffect(() => {
    if (overview || !error) return;
    const t = setInterval(fetchOverviewData, 5000);
    return () => clearInterval(t);
  }, [overview, error, fetchOverviewData]);

  useWebSocket(useCallback(msg => {
    if (REFRESH_EVENTS.includes(msg.type)) fetchOverviewData();
  }, [fetchOverviewData]));

  const generateBrief = async () => {
    setBriefStatus('generating');
    try {
      const res = await fetch(`${API}/api/morning-brief/generate`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
      setBriefStatus(null);
      fetchOverviewData();
    } catch (e) {
      setBriefStatus(e.message);
    }
  };

  const openThreat = (cveId) => {
    setThreatError(null);
    fetch(`${API}/api/cves/${encodeURIComponent(cveId)}`)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(setSelectedCve)
      .catch(e => setThreatError(`Could not open ${cveId} (${e.message}).`));
  };

  const loading = !overview && !error;
  const { metrics, severityBreakdown = [], activityLog = [], topThreats = [], morningBrief } = overview || {};
  const briefIsToday = morningBrief?.date && new Date(morningBrief.date).toDateString() === new Date().toDateString();
  const cvesToday = severityBreakdown.reduce((sum, b) => sum + b.value, 0);
  const generating = briefStatus === 'generating';

  const header = (
    <PageHeader
      title="Overview"
      description="Today's new CVEs, open incidents and the highest-risk vulnerabilities across all sources."
      actions={<>
        {updatedAt && <span style={{ color: 'var(--text-3)', fontSize: 'var(--fs-sm)' }}>Updated {formatTime(updatedAt)}</span>}
        <Button size="sm" icon={RotateCw} onClick={fetchOverviewData}>Refresh</Button>
      </>}
    />
  );

  // Never show zeros as if they were real numbers when nothing has loaded
  if (!overview && error) {
    return (
      <div className="page-container">
        {header}
        <Card>
          <ErrorState title="Could not load the overview" onRetry={fetchOverviewData}>
            The backend did not answer ({error}). It may still be starting; retrying every 5 seconds.
          </ErrorState>
        </Card>
      </div>
    );
  }

  return (
    <div className="page-container page-stack">
      {header}

      {error && (
        <ErrorState title="Showing the last loaded data" onRetry={fetchOverviewData}>
          The latest refresh failed ({error}).
        </ErrorState>
      )}

      {loading ? (
        <div className="kpi-strip" aria-busy="true">
          {[1, 2, 3, 4].map(i => <div className="kpi" key={i}><Skeleton width="60%" /><Skeleton width="30%" height={24} /></div>)}
        </div>
      ) : (
        <KpiStrip items={[
          { label: 'CVEs published today', value: metrics.totalCves },
          { label: 'Open incidents', value: metrics.openIncidents },
          { label: 'Critical CVEs', value: metrics.criticalThreats, note: 'All time' },
          { label: 'Agents reporting', value: `${metrics.agentsOnline} / ${metrics.assetsRegistered}`, note: metrics.assetsRegistered ? 'Online now / registered' : 'No endpoints registered' },
        ]} />
      )}

      <Card title="Top 5 by risk score" subtitle="All CVEs, ranked by ThreatLens risk score. Select a row for details." flush>
        <Table
          caption="Top 5 CVEs by risk score"
          columns={THREAT_COLUMNS}
          rows={topThreats}
          loading={loading}
          skeletonRows={5}
          onRowClick={t => openThreat(t.cve_id)}
          selectedKey={selectedCve?.id}
          emptyTitle="No scored CVEs yet"
          emptyText="CVEs appear here once the NVD sync has scored them."
        />
        {threatError && <div role="alert" className="inline-error">{threatError}</div>}
      </Card>

      <div className="grid-auto">
        <Card title="Risk bands" subtitle={loading ? 'CVEs published today' : `${cvesToday} CVE${cvesToday === 1 ? '' : 's'} published today`}>
          {loading ? <Skeleton lines={4} /> : cvesToday > 0
            ? <BandBars bands={severityBreakdown} />
            : <EmptyState title="No CVEs published yet today">The NVD sync runs every 15 minutes.</EmptyState>}
        </Card>

        <Card title="Activity" subtitle="Latest CVEs and incidents" flush>
          {loading ? <div className="card-body"><Skeleton lines={5} /></div> : activityLog.length === 0
            ? <EmptyState title="No recent activity" />
            : (
              <ul className="activity-list">
                {activityLog.slice(0, 10).map(a => (
                  <li key={a.id}>
                    <div className="activity-message">{a.message}</div>
                    <div className="activity-meta">
                      <span className="activity-type">{a.type}</span>
                      {severityKey(a.severity) && <Badge severity={a.severity} />}
                      <time className="activity-time mono" dateTime={a.timestamp} title={new Date(a.timestamp).toLocaleString()}>
                        {formatTimeAgo(a.timestamp, now)}
                      </time>
                    </div>
                  </li>
                ))}
              </ul>
            )}
        </Card>

        <Card
          title="Morning brief"
          subtitle={morningBrief?.date ? `GPT-4o · generated ${new Date(morningBrief.date).toLocaleString()}` : 'GPT-4o summary of top-risk CVEs, open incidents and OSINT alerts'}
          actions={!loading && (
            <Button size="sm" icon={generating ? Loader2 : Sparkles} onClick={generateBrief} disabled={generating}
              className={generating ? 'is-busy' : undefined}>
              {generating ? 'Generating…' : morningBrief?.content ? 'Regenerate' : 'Generate'}
            </Button>
          )}
        >
          {briefStatus && !generating && (
            <ErrorState title="Could not generate the brief">{briefStatus}</ErrorState>
          )}
          {loading ? <Skeleton lines={5} /> : morningBrief?.content ? (
            <>
              {!briefIsToday && <div style={{ marginBottom: 'var(--s2)' }}><Badge>Not from today</Badge></div>}
              <div className="brief-text">{morningBrief.content}</div>
            </>
          ) : !briefStatus && (
            <EmptyState title="No brief yet">Generate one to summarise the highest-risk CVEs, open incidents and recent OSINT alerts. It uses one GPT-4o request.</EmptyState>
          )}
        </Card>
      </div>

      <CveDrawer cve={selectedCve} onClose={() => setSelectedCve(null)} />
    </div>
  );
};

export default Overview;
