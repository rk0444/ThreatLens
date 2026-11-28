import { useState, useEffect } from 'react';
import { Eye, EyeOff, Monitor, Moon, Sun, Save } from 'lucide-react';
import { getThemePreference, setThemePreference } from '../utils/theme';
import { KEY_FIELDS } from '../utils/apiKeys';
import { PageHeader, Button, Card, Input, Tabs } from '../components/ui';

const TABS = [{ id: 'keys', label: 'API keys' }, { id: 'system', label: 'System' }, { id: 'about', label: 'About' }];

const Settings = () => {
  const desktop = Boolean(window.electronAPI);
  const [activeTab, setActiveTab] = useState('keys');
  const [keys, setKeys] = useState(Object.fromEntries(KEY_FIELDS.map(f => [f.name, ''])));
  const [showKeys, setShowKeys] = useState({});
  const [saveStatus, setSaveStatus] = useState(null);
  const [saving, setSaving] = useState(false);
  const [autoLaunch, setAutoLaunch] = useState(false);
  const [launchError, setLaunchError] = useState(null);
  const [version, setVersion] = useState(null);
  const [theme, setTheme] = useState(getThemePreference);

  useEffect(() => {
    if (!desktop) return;
    window.electronAPI.readEnv().then(env => {
      setKeys(prev => Object.fromEntries(Object.keys(prev).map(k => [k, env[k] || ''])));
    });
    window.electronAPI.getAppInfo().then(info => {
      setVersion(info.version);
      setAutoLaunch(Boolean(info.autoLaunch));
    });
  }, [desktop]);

  const handleSaveKeys = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await window.electronAPI.writeEnv(keys);
      setSaveStatus({ ok: true, text: 'Saved. Restart ThreatLens for the new keys to take effect.' });
    } catch (err) {
      setSaveStatus({ ok: false, text: `Could not save the keys (${err.message}).` });
    }
    setSaving(false);
  };

  const toggleAutoLaunch = async (val) => {
    setLaunchError(null);
    try {
      setAutoLaunch(await window.electronAPI.toggleAutoLaunch(val)); // what the OS actually accepted
    } catch (err) {
      setLaunchError(`Could not change this setting (${err.message}).`);
    }
  };

  const desktopOnly = <p className="muted">This setting can only be changed in the ThreatLens desktop app.</p>;

  return (
    <div className="page-container page-stack" style={{ maxWidth: 880 }}>
      <PageHeader title="Settings" description="Integrations, appearance and how ThreatLens starts." />

      <Card flush>
        <div style={{ padding: '0 var(--s4)' }}>
          <Tabs label="Settings sections" value={activeTab} onChange={setActiveTab} tabs={TABS} />
        </div>

        <div className="settings-body" role="tabpanel" aria-label={TABS.find(t => t.id === activeTab).label}>
          {activeTab === 'keys' && (
            <>
              <p className="muted">Keys are stored in ThreatLens's local .env file. A source without a key shows as unavailable in the top bar.</p>
              {!desktop ? desktopOnly : (
                <form onSubmit={handleSaveKeys} className="settings-form">
                  {KEY_FIELDS.map(({ name, label, hint }) => (
                    <div key={name} className="key-row">
                      <Input
                        id={name} label={label} hint={hint} className="key-input"
                        type={showKeys[name] ? 'text' : 'password'} value={keys[name]}
                        autoComplete="off" spellCheck={false}
                        onChange={e => { setKeys({ ...keys, [name]: e.target.value }); setSaveStatus(null); }}
                      />
                      <Button variant="ghost" iconOnly icon={showKeys[name] ? EyeOff : Eye}
                        onClick={() => setShowKeys({ ...showKeys, [name]: !showKeys[name] })}>
                        {showKeys[name] ? `Hide ${label} key` : `Show ${label} key`}
                      </Button>
                    </div>
                  ))}
                  <div className="settings-actions">
                    {saveStatus && <span role="status" className={saveStatus.ok ? 'small' : 'field-error'}>{saveStatus.text}</span>}
                    <Button type="submit" variant="primary" icon={Save} disabled={saving}>{saving ? 'Saving…' : 'Save keys'}</Button>
                  </div>
                </form>
              )}
            </>
          )}

          {activeTab === 'system' && (
            <div className="settings-rows">
              <div className="settings-row">
                <div>
                  <div id="theme-label" style={{ fontWeight: 600 }}>Theme</div>
                  <div className="small muted">System follows your Windows light or dark setting.</div>
                </div>
                <div className="segmented" role="radiogroup" aria-labelledby="theme-label">
                  {[['system', 'System', Monitor], ['dark', 'Dark', Moon], ['light', 'Light', Sun]].map(([id, label, Icon]) => (
                    <label key={id}>
                      <input type="radio" name="theme" value={id} checked={theme === id}
                        onChange={() => { setTheme(id); setThemePreference(id); }} />
                      <Icon size={14} aria-hidden="true" />{label}
                    </label>
                  ))}
                </div>
              </div>
              <div className="settings-row">
                <div>
                  <div style={{ fontWeight: 600 }}>Launch on startup</div>
                  <div className="small muted">Start ThreatLens automatically when you sign in to Windows.</div>
                  {launchError && <div role="alert" className="field-error">{launchError}</div>}
                </div>
                {!desktop ? desktopOnly : (
                  <label className="checkbox">
                    <input type="checkbox" checked={autoLaunch} onChange={e => toggleAutoLaunch(e.target.checked)} />
                    {autoLaunch ? 'On' : 'Off'}
                  </label>
                )}
              </div>
            </div>
          )}

          {activeTab === 'about' && (
            <dl className="kv" style={{ maxWidth: 420 }}>
              <div><dt>Application</dt><dd style={{ fontFamily: 'var(--font-sans)' }}>ThreatLens</dd></div>
              <div><dt>Version</dt><dd>{version || (desktop ? '…' : 'Shown in the desktop app')}</dd></div>
            </dl>
          )}
        </div>
      </Card>
    </div>
  );
};

export default Settings;
