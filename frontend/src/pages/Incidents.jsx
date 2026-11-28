import { useState, useEffect, useCallback } from 'react';
import { CheckCircle, Search as SearchIcon, FileText, Copy, Check, Loader2 } from 'lucide-react';
import CustomDropdown from '../components/CustomDropdown';
import { useWebSocket } from '../hooks/useWebSocket';
import { PageHeader, Button, Badge, Card, Table, Input, Modal, ErrorState } from '../components/ui';
import { severityKey } from '../utils/riskScore';

const API = 'http://127.0.0.1:8000';

const getJson = async (url, options) => {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `HTTP ${res.status}`);
  return data;
};

const timeAgo = (dateStr, now) => {
  const mins = Math.floor((now - new Date(dateStr).getTime()) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
};

// Workflow state, not risk: words on neutral badges, accent for incidents nobody has picked up
const statusBadge = (status) => (status === 'Resolved' ? <Badge tone="ok">Resolved</Badge>
  : status === 'Active' ? <Badge tone="accent">Active</Badge> : <Badge>{status}</Badge>);

const SEVERITY_OPTIONS = [{ value: 'All', label: 'All severities' }, ...['Critical', 'High', 'Medium', 'Low'].map(v => ({ value: v, label: v }))];
const STATUS_OPTIONS = [{ value: 'All', label: 'All statuses' }, ...['Active', 'Investigating', 'Resolved'].map(v => ({ value: v, label: v }))];

const formatTimelineTime = (t) => (t ? new Date(typeof t === 'number' ? t * 1000 : t).toLocaleString() : '');

const Incidents = () => {
  const [incidents, setIncidents] = useState([]);
  const [machineNames, setMachineNames] = useState({});
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [actionError, setActionError] = useState(null);
  const [acting, setActing]       = useState(false);
  const [newIds, setNewIds]       = useState(new Set());
  // A playbook belongs to the incident it was generated for; switching incidents mid-request can't mislabel it
  const [playbookResult, setPlaybookResult] = useState(null); // { incidentId, data }
  const [playbookLoadingId, setPlaybookLoadingId] = useState(null);
  const [analystNote, setAnalystNote] = useState('');
  const [filter, setFilter]       = useState({ severity: 'All', status: 'All' });
  const [copiedStep, setCopiedStep] = useState(null);
  const [now, setNow] = useState(() => Date.now());

  // Keep "x m ago" labels current while the page stays open
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60000);
    return () => clearInterval(t);
  }, []);

  // The open incident always comes from the latest list, so live updates reach it too
  const selected = incidents.find(i => i.id === selectedId) || null;
  const playbook = playbookResult?.incidentId === selectedId ? playbookResult.data : null;
  const playbookLoading = playbookLoadingId !== null && playbookLoadingId === selectedId;
  const machineLabel = (id) => machineNames[id] || `Machine #${id}`;

  const fetchIncidents = useCallback(() =>
    Promise.all([getJson(`${API}/api/incidents`), getJson(`${API}/api/assets`).catch(() => [])])
      .then(([list, assets]) => {
        setIncidents(list);
        setMachineNames(Object.fromEntries(assets.map(a => [a.id, a.name])));
        setError(null);
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false)), []);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);

  useWebSocket(useCallback(msg => {
    if (msg.type === 'NEW_INCIDENT') {
      const id = msg.data?.id;
      setNewIds(prev => new Set([...prev, id]));
      setTimeout(() => setNewIds(prev => { const n = new Set(prev); n.delete(id); return n; }), 10000);
    }
    if (['NEW_INCIDENT', 'INCIDENT_UPDATE', 'ASSET_DELETED'].includes(msg.type)) fetchIncidents();
  }, [fetchIncidents]));

  const selectIncident = (inc) => {
    setSelectedId(inc.id);
    setAnalystNote('');
    setActionError(null);
  };

  const handleRespond = async (action) => {
    if (!selected) return;
    setActionError(null);
    setActing(true);
    try {
      await getJson(`${API}/api/incidents/${selected.id}/respond`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, analyst_note: analystNote })
      });
      setAnalystNote('');
      fetchIncidents();
    } catch (e) {
      setActionError(`Could not update the incident (${e.message}).`);
    }
    setActing(false);
  };

  const copyCommand = async (text, step) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedStep(step);
      setTimeout(() => setCopiedStep(s => (s === step ? null : s)), 2000);
    } catch { /* clipboard blocked: the command stays visible to copy by hand */ }
  };

  const loadPlaybook = async () => {
    const incidentId = selected.id;
    setPlaybookLoadingId(incidentId);
    try {
      setPlaybookResult({ incidentId, data: await getJson(`${API}/api/incidents/${incidentId}/playbook`) });
    } catch (e) {
      setPlaybookResult({ incidentId, data: { error: e.message } });
    } finally {
      setPlaybookLoadingId(id => (id === incidentId ? null : id));
    }
  };

  const filtered = incidents.filter(inc =>
    (filter.severity === 'All' || inc.severity === filter.severity) && (filter.status === 'All' || inc.status === filter.status));
  const openCount = incidents.filter(i => i.status !== 'Resolved').length;

  return (
    <div className="page-container page-stack">
      <PageHeader
        title="Incidents"
        description={loading ? 'Filed by the network and process monitors.' : `${openCount} open of ${incidents.length}. Filed by the network and process monitors; status changes are made by you.`}
      />

      <div className="toolbar" role="group" aria-label="Filters">
        <CustomDropdown label="Severity" hideLabel options={SEVERITY_OPTIONS} value={filter.severity} onChange={v => setFilter(f => ({ ...f, severity: v }))} />
        <CustomDropdown label="Status" hideLabel options={STATUS_OPTIONS} value={filter.status} onChange={v => setFilter(f => ({ ...f, status: v }))} />
        {!loading && <span className="small muted" role="status">{filtered.length} incident{filtered.length === 1 ? '' : 's'}</span>}
      </div>

      <Card flush>
        <Table
          caption="Incidents"
          rows={filtered}
          loading={loading}
          error={error && incidents.length === 0 ? `Could not load incidents (${error}). Is the backend running?` : null}
          onRetry={fetchIncidents}
          onRowClick={selectIncident}
          selectedKey={selectedId}
          maxHeight="calc(100vh - 250px)"
          emptyTitle={incidents.length === 0 ? 'No incidents yet' : 'No incidents match these filters'}
          emptyText={incidents.length === 0 ? 'The network and process monitors file one when they detect something.' : undefined}
          columns={[
            { key: 'severity', header: 'Severity', width: 104, render: i => (severityKey(i.severity) ? <Badge severity={i.severity} /> : <Badge>{i.severity}</Badge>) },
            { key: 'status', header: 'Status', width: 120, render: i => statusBadge(i.status) },
            { key: 'type', header: 'Incident', width: 220, render: i => <span>{i.type}{newIds.has(i.id) && <> <Badge tone="accent">New</Badge></>}</span> },
            { key: 'evidence', header: 'Process or connection', truncate: true, render: i => <span className="mono" title={i.process_name || i.network_connection || ''}>{i.process_name || i.network_connection || '–'}</span> },
            { key: 'machine_id', header: 'Endpoint', width: 150, truncate: true, render: i => machineLabel(i.machine_id) },
            { key: 'created_at', header: 'Filed', width: 96, render: i => <span title={new Date(i.created_at).toLocaleString()}>{timeAgo(i.created_at, now)}</span> },
          ]}
        />
        {error && incidents.length > 0 && <div role="alert" className="inline-error">The latest refresh failed ({error}). Showing the last loaded incidents.</div>}
      </Card>

      <Modal
        drawer
        open={Boolean(selected)}
        onClose={() => setSelectedId(null)}
        title={selected && (
          <span style={{ display: 'grid', gap: 'var(--s1)' }}>
            <span>{selected.type}</span>
            <span style={{ display: 'flex', gap: 'var(--s2)', alignItems: 'center', fontWeight: 400 }}>
              {severityKey(selected.severity) ? <Badge severity={selected.severity} /> : <Badge>{selected.severity}</Badge>}
              {statusBadge(selected.status)}
              <span className="small muted">INC-{selected.id} · {machineLabel(selected.machine_id)}</span>
            </span>
          </span>
        )}
      >
        {selected && (
          <div className="stack">
            {selected.details && (
              <section>
                <h3 className="section-title">What the monitor recorded</h3>
                <p>{selected.details}</p>
              </section>
            )}

            <dl className="facts">
              <div><dt>Filed</dt><dd className="fact-text">{new Date(selected.created_at).toLocaleString()}</dd></div>
              {selected.process_name && <div><dt>Process</dt><dd className="small">{selected.process_name}</dd></div>}
              {selected.network_connection && <div><dt>Network</dt><dd className="small">{selected.network_connection}</dd></div>}
            </dl>
            {selected.file_path && (
              <section><h3 className="section-title">File path</h3><code className="code-block">{selected.file_path}</code></section>
            )}

            <section>
              <h3 className="section-title">Timeline</h3>
              {!selected.timeline?.length ? <p className="muted">No timeline entries yet.</p> : (
                <ol className="timeline">
                  {selected.timeline.map((entry, idx) => (
                    <li key={idx}>
                      <div className="small muted">{formatTimelineTime(entry.time)}{entry.actor && ` · ${entry.actor}`}</div>
                      <div>{entry.action || entry.event}</div>
                    </li>
                  ))}
                </ol>
              )}
            </section>

            {selected.sandbox_verdict && (
              <details className="disclosure">
                <summary>Sandbox report: {selected.sandbox_verdict}</summary>
                <pre className="code-block">{JSON.stringify(selected.virustotal_result || { note: 'Full sandbox data stored in database.' }, null, 2)}</pre>
              </details>
            )}

            {selected.status !== 'Resolved' && (
              <section>
                <h3 className="section-title">Analyst action</h3>
                <p className="small muted" style={{ marginBottom: 'var(--s2)' }}>ThreatLens takes no automatic response actions; set the status here once you have checked the machine.</p>
                <Input multiline rows={2} label="Analyst note (optional, saved in the timeline)" value={analystNote} onChange={e => setAnalystNote(e.target.value)} />
                {actionError && <div role="alert" className="field-error" style={{ marginTop: 'var(--s2)' }}>{actionError}</div>}
                <div style={{ display: 'flex', gap: 'var(--s2)', marginTop: 'var(--s3)', flexWrap: 'wrap' }}>
                  {selected.status !== 'Investigating' && (
                    <Button icon={SearchIcon} onClick={() => handleRespond('investigate')} disabled={acting}>Mark investigating</Button>
                  )}
                  <Button variant="primary" icon={CheckCircle} onClick={() => handleRespond('resolve')} disabled={acting}>Resolve</Button>
                </div>
              </section>
            )}

            <section>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--s2)', marginBottom: 'var(--s2)' }}>
                <h3 className="section-title" style={{ margin: 0 }}>Remediation playbook (GPT-4o)</h3>
                <Button size="sm" icon={playbookLoading ? Loader2 : FileText} className={playbookLoading ? 'is-busy' : undefined}
                  onClick={loadPlaybook} disabled={playbookLoading}>
                  {playbookLoading ? 'Generating…' : playbook && !playbook.error ? 'Regenerate' : 'Generate'}
                </Button>
              </div>
              {playbook?.error ? (
                <ErrorState title="Could not generate the playbook">{playbook.error}</ErrorState>
              ) : !playbook ? (
                <p className="muted">Generates steps from this incident's recorded fields. Uses one GPT-4o request.</p>
              ) : (
                <>
                  <ol className="playbook">
                    {playbook.steps?.map((step, i) => (
                      <li key={i}>
                        <span className="playbook-num mono" aria-hidden="true">{step.step}</span>
                        <div style={{ display: 'grid', gap: 'var(--s2)', minWidth: 0 }}>
                          <div style={{ fontWeight: 500 }}>{step.action}</div>
                          {step.command && (
                            <div className="command">
                              <code>{step.command}</code>
                              <Button variant="ghost" size="sm" iconOnly icon={copiedStep === i ? Check : Copy} onClick={() => copyCommand(step.command, i)}>
                                {copiedStep === i ? 'Copied' : 'Copy command'}
                              </Button>
                            </div>
                          )}
                          <div style={{ display: 'flex', gap: 'var(--s2)', alignItems: 'center', flexWrap: 'wrap' }} className="small">
                            {step.priority && <Badge>Priority: {step.priority}</Badge>}
                            {step.risk_level && (severityKey(step.risk_level) ? <Badge severity={step.risk_level}>{step.risk_level} risk</Badge> : <Badge>{step.risk_level} risk</Badge>)}
                            {step.estimated_time && <span className="muted">About {step.estimated_time}</span>}
                          </div>
                        </div>
                      </li>
                    ))}
                  </ol>
                  <p className="small muted" style={{ marginTop: 'var(--s3)' }}>
                    Generated by GPT-4o from this incident's recorded fields, {new Date(playbook.generated_at).toLocaleString()}. Review every command before running it.
                  </p>
                </>
              )}
            </section>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default Incidents;
