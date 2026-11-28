import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Check, ShieldCheck, Plus, X, Loader2 } from 'lucide-react';
import { Button, Badge, Input, ErrorState } from '../components/ui';
import CustomDropdown from '../components/CustomDropdown';
import { KEY_FIELDS } from '../utils/apiKeys';

const API = 'http://127.0.0.1:8000';
const STEPS = ['Welcome', 'API keys', 'Endpoints', 'This computer', 'Done'];
const OS_OPTIONS = ['Windows', 'macOS', 'Linux'].map(v => ({ value: v, label: v }));
const COMMON_SOFTWARE = ['Apache', 'Nginx', 'MySQL', 'PostgreSQL', 'Node.js', 'Python', 'Docker', 'OpenSSL'];
const EMPTY_ASSET = { hostname: '', os: 'Windows', ip_address: '', software_list: [] };

const postJson = async (url, body) => {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${res.status})`);
  return data;
};

const formatSeen = (iso) => (iso ? new Date(iso).toLocaleString() : 'never');

const Onboarding = () => {
  const navigate = useNavigate();
  const desktop = Boolean(window.electronAPI);
  const [step, setStep] = useState(0);
  const [keys, setKeys] = useState(Object.fromEntries(KEY_FIELDS.map(f => [f.name, ''])));
  const [keysSaved, setKeysSaved] = useState(0);
  const [asset, setAsset] = useState(EMPTY_ASSET);
  const [softwareInput, setSoftwareInput] = useState('');
  const [registered, setRegistered] = useState([]); // names registered in this session
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState(null);
  const [assets, setAssets] = useState(null);
  const [assetsError, setAssetsError] = useState(null);

  const next = () => { setFormError(null); setStep(s => Math.min(s + 1, STEPS.length - 1)); };
  const back = () => { setFormError(null); setStep(s => Math.max(s - 1, 0)); };

  // The network monitor on this computer registers it by hostname and marks it online with its heartbeat
  useEffect(() => {
    if (step < 3) return;
    let alive = true;
    const load = () => fetch(`${API}/api/assets`)
      .then(r => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(list => { if (alive) { setAssets(list); setAssetsError(null); } })
      .catch(e => { if (alive) setAssetsError(e.message); });
    load();
    const t = setInterval(load, 3000);
    return () => { alive = false; clearInterval(t); };
  }, [step]);

  const saveKeys = async () => {
    const filled = Object.fromEntries(Object.entries(keys).filter(([, v]) => v.trim()));
    if (Object.keys(filled).length === 0) { next(); return; }
    setBusy(true);
    try {
      await window.electronAPI.writeEnv(filled);
      setKeysSaved(Object.keys(filled).length);
      next();
    } catch (e) {
      setFormError(`Could not save the keys (${e.message}).`);
    }
    setBusy(false);
  };

  const addSoftware = (name) => {
    const sw = name.trim();
    if (sw && !asset.software_list.includes(sw)) setAsset(a => ({ ...a, software_list: [...a.software_list, sw] }));
  };

  // andContinue: false keeps the form open (cleared) to register another endpoint
  const saveAsset = async (andContinue) => {
    if (!asset.hostname.trim() || !asset.ip_address.trim()) { setFormError('Hostname and IP address are required.'); return; }
    setBusy(true);
    setFormError(null);
    try {
      await postJson(`${API}/api/assets`, {
        name: asset.hostname.trim(), os: asset.os, ip_address: asset.ip_address.trim(), software_list: asset.software_list,
      });
      setRegistered(r => [...r, asset.hostname.trim()]);
      setAsset(EMPTY_ASSET);
      setSoftwareInput('');
      if (andContinue) next();
    } catch (e) {
      setFormError(`Could not register the endpoint (${e.message}).`);
    }
    setBusy(false);
  };

  const online = (assets || []).filter(a => a.online);

  return (
    <div className="onboarding">
      <nav className="onboarding-steps" aria-label="Setup steps">
        <div className="brand-inline"><ShieldCheck size={18} aria-hidden="true" /> ThreatLens setup</div>
        <ol>
          {STEPS.map((name, i) => (
            <li key={name} className={i === step ? 'current' : i < step ? 'done' : undefined} aria-current={i === step ? 'step' : undefined}>
              <span className="step-mark" aria-hidden="true">{i < step ? <Check size={12} /> : i + 1}</span>
              {name}
            </li>
          ))}
        </ol>
      </nav>

      <section className="onboarding-body" aria-labelledby="step-title">
        <div className="small muted">Step {step + 1} of {STEPS.length}</div>

        {step === 0 && (<>
          <h1 id="step-title">Set up ThreatLens</h1>
          <p>ThreatLens collects published vulnerabilities (NVD, EPSS, CISA KEV) and threat intelligence (AlienVault OTX, MITRE ATT&CK), scores them for your endpoints, and watches this computer's network connections and processes.</p>
          <p className="muted">Setup takes a few minutes. Every step can be skipped and changed later in Settings or Endpoints.</p>
          <div className="onboarding-actions"><span /><Button variant="primary" onClick={next}>Start setup</Button></div>
        </>)}

        {step === 1 && (<>
          <h1 id="step-title">API keys</h1>
          <p className="muted">All keys are optional. Without one, that source shows as unavailable. Keys are stored in ThreatLens's local .env file and apply after a restart.</p>
          {!desktop ? (
            <p className="muted">Keys can only be entered in the ThreatLens desktop app.</p>
          ) : (
            <div className="onboarding-fields">
              {KEY_FIELDS.map(f => (
                <Input key={f.name} label={f.label} hint={f.hint} type="password" autoComplete="off" spellCheck={false}
                  value={keys[f.name]} onChange={e => setKeys(k => ({ ...k, [f.name]: e.target.value }))} />
              ))}
            </div>
          )}
          {formError && <ErrorState title="Not saved">{formError}</ErrorState>}
          <div className="onboarding-actions">
            <Button variant="ghost" onClick={back}>Back</Button>
            <div style={{ display: 'flex', gap: 'var(--s2)' }}>
              <Button onClick={next}>Skip</Button>
              {desktop && <Button variant="primary" onClick={saveKeys} disabled={busy}>Save and continue</Button>}
            </div>
          </div>
        </>)}

        {step === 2 && (<>
          <h1 id="step-title">Register endpoints</h1>
          <p className="muted">
            This computer registers itself when its monitor starts (next step). Add other machines here so their software is matched against CVEs, or skip and add them later on the Endpoints page.
          </p>
          {registered.length > 0 && (
            <div className="small">Registered: {registered.map(n => <Badge key={n} tone="ok">{n}</Badge>)}</div>
          )}
          <div className="onboarding-fields">
            <Input label="Hostname" value={asset.hostname} placeholder="e.g. SRV-PROD-01" autoComplete="off"
              onChange={e => setAsset(a => ({ ...a, hostname: e.target.value }))} />
            <div className="field">
              <CustomDropdown label="Operating system" options={OS_OPTIONS} value={asset.os} onChange={v => setAsset(a => ({ ...a, os: v }))} />
            </div>
            <Input label="IP address" value={asset.ip_address} placeholder="e.g. 192.168.1.100" autoComplete="off" className="mono-input"
              onChange={e => setAsset(a => ({ ...a, ip_address: e.target.value }))} />
            <div className="field">
              <Input label="Installed software" value={softwareInput} placeholder="Type a name and press Enter"
                hint="Names are matched against the products NVD lists for each CVE."
                onChange={e => setSoftwareInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addSoftware(softwareInput); setSoftwareInput(''); } }} />
              {asset.software_list.length > 0 && (
                <ul className="tag-list" aria-label="Software added">
                  {asset.software_list.map(sw => (
                    <li key={sw} className="badge">
                      {sw}
                      <button type="button" className="tag-remove" aria-label={`Remove ${sw}`}
                        onClick={() => setAsset(a => ({ ...a, software_list: a.software_list.filter(s => s !== sw) }))}><X size={12} /></button>
                    </li>
                  ))}
                </ul>
              )}
              <div className="tag-suggestions">
                <span className="small muted">Common:</span>
                {COMMON_SOFTWARE.filter(sw => !asset.software_list.includes(sw)).map(sw => (
                  <Button key={sw} size="sm" variant="ghost" icon={Plus} onClick={() => addSoftware(sw)}>{sw}</Button>
                ))}
              </div>
            </div>
          </div>
          {formError && <ErrorState title="Not registered">{formError}</ErrorState>}
          <div className="onboarding-actions">
            <Button variant="ghost" onClick={back}>Back</Button>
            <div style={{ display: 'flex', gap: 'var(--s2)', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
              <Button onClick={next}>{registered.length ? 'Continue' : 'Skip'}</Button>
              <Button onClick={() => saveAsset(false)} disabled={busy}>Register and add another</Button>
              <Button variant="primary" onClick={() => saveAsset(true)} disabled={busy}>Register and continue</Button>
            </div>
          </div>
        </>)}

        {step === 3 && (<>
          <h1 id="step-title">This computer</h1>
          <p className="muted">
            ThreatLens starts a network monitor and a process monitor on this computer. The network monitor registers the computer by its hostname and checks in every 10 seconds; that check-in is what marks it online.
          </p>
          <div className="callout" role="status" aria-live="polite">
            {assetsError ? (
              <div><div className="callout-title">Backend unreachable</div><div className="callout-text">{assetsError}. Retrying every 3 seconds.</div></div>
            ) : assets == null ? (
              <div className="callout-text" style={{ display: 'flex', gap: 'var(--s2)', alignItems: 'center' }}><Loader2 size={14} className="spin" aria-hidden="true" /> Checking…</div>
            ) : online.length > 0 ? (
              <div>
                <div className="callout-title">Monitor checking in</div>
                <div className="callout-text">{online.map(a => `${a.name} (last check-in ${formatSeen(a.last_seen)})`).join(', ')}</div>
              </div>
            ) : (
              <div>
                <div className="callout-title">Waiting for the monitor to check in</div>
                <div className="callout-text">
                  The installed app starts it automatically. When running from source, <code>npm run dev</code> starts it, or run <code>npm run monitor:dev</code> on its own.
                </div>
              </div>
            )}
          </div>
          <div className="onboarding-actions">
            <Button variant="ghost" onClick={back}>Back</Button>
            <Button variant="primary" onClick={next}>{online.length ? 'Continue' : 'Continue without it'}</Button>
          </div>
        </>)}

        {step === 4 && (<>
          <h1 id="step-title">Setup summary</h1>
          <ul className="summary-list">
            <li>
              <span>API keys</span>
              <span>{keysSaved ? `${keysSaved} saved; restart ThreatLens to apply them` : desktop ? 'None entered' : 'Not available outside the desktop app'}</span>
            </li>
            <li><span>Endpoints registered in setup</span><span>{registered.length ? registered.join(', ') : 'None'}</span></li>
            <li><span>Endpoints known to ThreatLens</span><span>{assets ? assets.length : '–'}</span></li>
            <li><span>Monitor on this computer</span><span>{online.length ? 'Checking in' : 'Not checking in yet'}</span></li>
          </ul>
          <p className="muted">Data syncs run in the background: NVD every 15 minutes, OSINT every 30 minutes, CISA KEV every 6 hours.</p>
          <div className="onboarding-actions">
            <Button variant="ghost" onClick={back}>Back</Button>
            <Button variant="primary" onClick={() => navigate('/')}>Open Overview</Button>
          </div>
        </>)}
      </section>
    </div>
  );
};

export default Onboarding;
