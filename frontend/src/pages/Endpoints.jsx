import { useState, useEffect, useCallback } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import CustomDropdown from '../components/CustomDropdown';
import { useWebSocket } from '../hooks/useWebSocket';
import { PageHeader, Button, Badge, Card, KpiStrip, Table, Input, Modal, ErrorState, Skeleton } from '../components/ui';

const API = 'http://127.0.0.1:8000';
const REFRESH_EVENTS = ['ASSET_ADDED', 'ASSET_DELETED', 'ASSET_UPDATED', 'CVES_UPDATED', 'NEW_INCIDENT', 'INCIDENT_UPDATE'];
const EMPTY_FORM = { name: '', os: 'Windows 11 Pro', ip_address: '', software_list: '' };
const OS_OPTIONS = ['Windows 11 Pro', 'Windows 10 Pro', 'Windows Server 2022', 'Ubuntu 22.04', 'macOS Ventura', 'Debian 12', 'CentOS 9']
  .map(v => ({ value: v, label: v }));

// Online/offline comes from the server (agent heartbeat within the last minute); this only words the last check-in
const formatCheckin = (lastSeen, online, now) => {
  if (!lastSeen) return 'Never';
  if (online) return 'Just now';
  const mins = Math.floor((now - new Date(lastSeen).getTime()) / 60000);
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return new Date(lastSeen).toLocaleDateString();
};

const statusBadge = (asset) => (asset.online ? <Badge tone="ok">Online</Badge> : <Badge>Offline</Badge>);

const exposure = (asset) => {
  if (!(asset.software_list || []).length) return <span className="muted">No software listed</span>;
  if (!asset.top_cve) return <span className="muted">0</span>;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--s2)' }}>
      <span className="mono">{asset.matching_cve_count}</span>
      <Badge severity={asset.top_cve.risk_band}>top {Number(asset.top_cve.risk_score).toFixed(1)}</Badge>
    </span>
  );
};

const getJson = async (url, options) => {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = typeof data.detail === 'string' ? data.detail : Array.isArray(data.detail) ? data.detail.map(d => d.msg).join('; ') : null;
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return data;
};

export default function Endpoints() {
  const [assets, setAssets]         = useState([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [actionError, setActionError] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [assetIncs, setAssetIncs]   = useState(null);
  const [showAdd, setShowAdd]       = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [form, setForm]             = useState(EMPTY_FORM);
  const [formError, setFormError]   = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [now, setNow]               = useState(() => Date.now());

  const fetchAssets = useCallback(() =>
    getJson(`${API}/api/assets`)
      .then(d => { setAssets(d); setError(null); setNow(Date.now()); })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false)), []);

  useEffect(() => { fetchAssets(); }, [fetchAssets]);

  // Heartbeats don't broadcast, so re-check online/offline every 30 s
  useEffect(() => {
    const t = setInterval(fetchAssets, 30000);
    return () => clearInterval(t);
  }, [fetchAssets]);

  useWebSocket(useCallback(msg => {
    if (REFRESH_EVENTS.includes(msg.type)) fetchAssets();
  }, [fetchAssets]));

  // The open drawer reads the latest refresh, so its numbers never go stale
  const selected = assets.find(a => a.id === selectedId) || null;

  const openDetail = (asset) => {
    setSelectedId(asset.id);
    setAssetIncs(null);
    getJson(`${API}/api/assets/${asset.id}/incidents`).then(setAssetIncs).catch(() => setAssetIncs([]));
  };

  const handleAdd = async () => {
    if (!form.name.trim() || !form.ip_address.trim()) { setFormError('Hostname and IP address are required.'); return; }
    setSubmitting(true);
    setFormError(null);
    const payload = { ...form, name: form.name.trim(), ip_address: form.ip_address.trim(), software_list: form.software_list.split(',').map(s => s.trim()).filter(Boolean) };
    try {
      await getJson(`${API}/api/assets`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      setShowAdd(false);
      setForm(EMPTY_FORM);
      fetchAssets();
    } catch (e) {
      setFormError(`Could not register the endpoint (${e.message}).`);
    }
    setSubmitting(false);
  };

  const handleDelete = async () => {
    setConfirmRemove(false);
    try {
      await getJson(`${API}/api/assets/${selectedId}`, { method: 'DELETE' });
      setSelectedId(null);
      fetchAssets();
    } catch (e) {
      setActionError(`Could not remove the endpoint (${e.message}).`);
    }
  };

  const onlineCount = assets.filter(a => a.online).length;
  const software = selected?.software_list || [];

  return (
    <div className="page-container page-stack">
      <PageHeader
        title="Endpoints"
        description="Machines whose software is matched against CVEs. A machine is online while its network monitor checks in."
        actions={<Button variant="primary" icon={Plus} onClick={() => { setFormError(null); setShowAdd(true); }}>Register endpoint</Button>}
      />

      {actionError && <Card flush><ErrorState title="Not removed">{actionError}</ErrorState></Card>}

      {loading ? (
        <div className="kpi-strip" aria-busy="true">{[1, 2, 3, 4].map(i => <div className="kpi" key={i}><Skeleton width="50%" /><Skeleton width="25%" height={24} /></div>)}</div>
      ) : !(error && assets.length === 0) && (
        <KpiStrip items={[
          { label: 'Endpoints', value: assets.length },
          { label: 'Online', value: onlineCount },
          { label: 'Offline', value: assets.length - onlineCount },
          { label: 'Open incidents', value: assets.reduce((s, a) => s + (a.open_incident_count || 0), 0) },
        ]} />
      )}

      <Card flush>
        <Table
          caption="Endpoints"
          rows={assets}
          loading={loading}
          error={error && assets.length === 0 ? `Could not load endpoints (${error}). Is the backend running?` : null}
          onRetry={fetchAssets}
          onRowClick={openDetail}
          selectedKey={selectedId}
          emptyTitle="No endpoints yet"
          emptyText="The network monitor registers this computer when it runs. Use Register endpoint to add other machines."
          columns={[
            { key: 'online', header: 'Status', width: 96, render: statusBadge },
            { key: 'name', header: 'Endpoint', width: 180, render: a => <strong>{a.name}</strong> },
            { key: 'os', header: 'OS', width: 150, truncate: true, render: a => <span title={a.os}>{a.os}</span> },
            { key: 'ip_address', header: 'IP address', mono: true, width: 130 },
            { key: 'last_seen', header: 'Last check-in', width: 120, render: a => <span title={a.last_seen ? new Date(a.last_seen).toLocaleString() : undefined}>{formatCheckin(a.last_seen, a.online, now)}</span> },
            { key: 'open_incident_count', header: 'Open incidents', align: 'right', mono: true, width: 120, render: a => a.open_incident_count || 0 },
            { key: 'matching_cve_count', header: 'Matching CVEs', width: 170, render: exposure },
            { key: 'latest_incident_summary', header: 'Latest incident', truncate: true, render: a => (a.latest_incident_summary ? <span title={a.latest_incident_summary}>{a.latest_incident_summary}</span> : <span className="muted">None</span>) },
          ]}
        />
        {error && assets.length > 0 && <div role="alert" className="inline-error">The latest refresh failed ({error}). Showing the last loaded data.</div>}
      </Card>

      {/* Detail drawer */}
      <Modal
        drawer
        open={Boolean(selected)}
        onClose={() => setSelectedId(null)}
        title={selected && (
          <span style={{ display: 'grid', gap: 2 }}>
            <span>{selected.name}</span>
            <span className="small muted mono" style={{ fontWeight: 400 }}>{selected.ip_address}</span>
          </span>
        )}
        footer={selected && <Button variant="danger" icon={Trash2} onClick={() => setConfirmRemove(true)}>Remove endpoint</Button>}
      >
        {selected && (
          <div className="stack">
            <dl className="facts">
              <div><dt>Status</dt><dd>{statusBadge(selected)}</dd></div>
              <div><dt>Last check-in</dt><dd className="fact-text">{selected.last_seen ? new Date(selected.last_seen).toLocaleString() : 'Never'}</dd></div>
              <div><dt>Operating system</dt><dd className="fact-text">{selected.os}</dd></div>
              <div><dt>Open incidents</dt><dd>{selected.open_incident_count || 0}</dd></div>
              <div><dt>Matching CVEs</dt><dd>{software.length ? selected.matching_cve_count : <span className="fact-text muted">No software listed</span>}</dd></div>
              <div>
                <dt>Highest CVE risk</dt>
                <dd>{selected.top_cve
                  ? <><Badge severity={selected.top_cve.risk_band} /> {Number(selected.top_cve.risk_score).toFixed(1)} <span className="small muted">{selected.top_cve.cve_id}</span></>
                  : '–'}</dd>
              </div>
            </dl>

            <section>
              <h3 className="section-title">Installed software ({software.length})</h3>
              {software.length === 0 ? <p className="muted">No software listed.</p> : (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s1)' }}>
                  {software.map(pkg => (
                    <Badge key={pkg}>{pkg}{selected.software_versions?.[pkg] && <span className="muted mono" style={{ fontWeight: 400 }}>{selected.software_versions[pkg]}</span>}</Badge>
                  ))}
                </div>
              )}
            </section>

            <section>
              <h3 className="section-title">Recent incidents{assetIncs ? ` (${assetIncs.length})` : ''}</h3>
              {assetIncs == null ? <Skeleton lines={3} /> : assetIncs.length === 0 ? <p className="muted">No incidents on this endpoint.</p> : (
                <ul className="map-list">
                  {assetIncs.slice(0, 5).map(inc => (
                    <li key={inc.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--s2)', alignItems: 'center' }}>
                      <div>
                        <div style={{ fontWeight: 600 }}>{inc.type}</div>
                        <div className="small muted">{new Date(inc.created_at).toLocaleString()} · {inc.status}</div>
                      </div>
                      <Badge severity={inc.severity} />
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        )}
      </Modal>

      {/* Remove confirmation */}
      <Modal
        open={confirmRemove}
        onClose={() => setConfirmRemove(false)}
        title="Remove this endpoint?"
        footer={<>
          <Button onClick={() => setConfirmRemove(false)}>Cancel</Button>
          <Button variant="danger" icon={Trash2} onClick={handleDelete}>Remove</Button>
        </>}
      >
        <p><strong>{selected?.name}</strong> and all incidents recorded for it will be deleted. This cannot be undone.</p>
        <p className="muted small" style={{ marginTop: 'var(--s2)' }}>If its network monitor is still running, it registers the machine again on its next check-in.</p>
      </Modal>

      {/* Register endpoint */}
      <Modal
        open={showAdd}
        onClose={() => setShowAdd(false)}
        title="Register endpoint"
        footer={<>
          <Button onClick={() => setShowAdd(false)}>Cancel</Button>
          <Button variant="primary" type="submit" form="register-endpoint" disabled={submitting}>{submitting ? 'Registering…' : 'Register'}</Button>
        </>}
      >
        <form id="register-endpoint" className="onboarding-fields" style={{ maxWidth: 'none' }} onSubmit={e => { e.preventDefault(); handleAdd(); }}>
          <Input label="Hostname" value={form.name} placeholder="e.g. WS-DEV-02" autoComplete="off" onChange={e => setForm({ ...form, name: e.target.value })} />
          <Input label="IP address" className="mono-input" value={form.ip_address} placeholder="e.g. 192.168.1.52" autoComplete="off" onChange={e => setForm({ ...form, ip_address: e.target.value })} />
          <div className="field">
            <CustomDropdown label="Operating system" options={OS_OPTIONS} value={form.os} onChange={val => setForm({ ...form, os: val })} />
          </div>
          <Input label="Installed software" hint="Comma-separated. Names are matched against the products NVD lists for each CVE."
            value={form.software_list} placeholder="Chrome, VS Code, Python" onChange={e => setForm({ ...form, software_list: e.target.value })} />
          {formError && <div role="alert" className="field-error">{formError}</div>}
        </form>
      </Modal>
    </div>
  );
}
