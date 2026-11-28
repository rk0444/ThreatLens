import React, { useState, useEffect } from 'react';
import { Key, Power, Info, Eye, EyeOff, Shield } from 'lucide-react';

// The names the backend reads (backend/services/*, backend/main.py)
const KEY_FIELDS = [
  { name: 'NVD_API_KEY', label: 'NVD', hint: 'Faster CVE sync from the National Vulnerability Database.' },
  { name: 'OTX_API_KEY', label: 'AlienVault OTX', hint: 'OSINT pulses on Global Threats.' },
  { name: 'ABUSEIPDB_API_KEY', label: 'AbuseIPDB', hint: 'IP reputation for the network monitor and IOC Hunter.' },
  { name: 'VIRUSTOTAL_API_KEY', label: 'VirusTotal', hint: 'File hash, URL and domain lookups in IOC Hunter.' },
  { name: 'GPT4O_API_KEY', label: 'GPT-4o', hint: 'AI Copilot, CVE summaries and the morning brief.' },
];

const Settings = () => {
  const desktop = Boolean(window.electronAPI);
  const [activeTab, setActiveTab] = useState('keys');
  const [keys, setKeys] = useState(Object.fromEntries(KEY_FIELDS.map(f => [f.name, ''])));
  const [showKeys, setShowKeys] = useState({});
  const [saveStatus, setSaveStatus] = useState(null);
  const [autoLaunch, setAutoLaunch] = useState(false);
  const [version, setVersion] = useState(null);

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

  const handleSaveKeys = async () => {
    try {
      await window.electronAPI.writeEnv(keys);
      setSaveStatus({ ok: true, text: 'Saved. Restart ThreatLens for the new keys to take effect.' });
    } catch (e) {
      setSaveStatus({ ok: false, text: `Could not save the keys (${e.message}).` });
    }
  };

  const toggleAutoLaunch = async (val) => {
    setAutoLaunch(await window.electronAPI.toggleAutoLaunch(val)); // what the OS actually accepted
  };

  const tabs = [
    { id: 'keys', label: 'API Keys', icon: <Key size={18} /> },
    { id: 'system', label: 'System', icon: <Power size={18} /> },
    { id: 'about', label: 'About', icon: <Info size={18} /> }
  ];

  const desktopOnly = (
    <p style={{ color: 'var(--text-muted)' }}>This setting can only be changed in the ThreatLens desktop app.</p>
  );

  return (
    <div className="page-container" style={{ padding: '24px' }}>
      <div className="label-small">Configuration</div>
      <h1 style={{ marginBottom: '2rem' }}>System <span className="italic-serif" style={{color: 'var(--accent-gold)'}}>Settings</span></h1>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2rem', alignItems: 'flex-start' }}>

        {/* Sidebar Tabs */}
        <div className="glass-panel" style={{ padding: '1rem', flex: '0 1 250px', minWidth: '200px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem 1rem',
                  background: activeTab === tab.id ? 'rgba(184, 146, 42, 0.1)' : 'transparent',
                  color: activeTab === tab.id ? 'var(--accent-gold)' : 'var(--text-secondary)',
                  border: 'none', borderLeft: activeTab === tab.id ? '2px solid var(--accent-gold)' : '2px solid transparent',
                  borderRadius: '0 4px 4px 0', cursor: 'pointer', textAlign: 'left',
                  transition: 'all 0.2s', fontSize: '0.9rem', fontWeight: 500
                }}
              >
                {tab.icon} {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Content Area */}
        <div className="glass-panel" style={{ padding: '2rem', minHeight: '400px', flex: '1 1 400px', minWidth: 0 }}>

          {/* API Keys */}
          {activeTab === 'keys' && (
            <div>
              <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem' }}>API Keys</h2>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '2rem' }}>
                Keys are stored in ThreatLens's local .env file. A source without a key shows as unavailable.
              </p>

              {!desktop ? desktopOnly : (
                <>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    {KEY_FIELDS.map(({ name, label, hint }) => (
                      <div key={name}>
                        <label htmlFor={name} style={{ display: 'block', marginBottom: '4px', fontSize: '0.9rem' }}>{label}</label>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>{hint}</div>
                        <div style={{ position: 'relative' }}>
                          <input
                            id={name}
                            type={showKeys[name] ? 'text' : 'password'}
                            value={keys[name]}
                            autoComplete="off"
                            spellCheck={false}
                            onChange={(e) => { setKeys({ ...keys, [name]: e.target.value }); setSaveStatus(null); }}
                            style={{
                              width: '100%', padding: '10px', paddingRight: '40px', borderRadius: '4px', boxSizing: 'border-box',
                              background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', color: 'var(--text-primary)'
                            }}
                          />
                          <button
                            type="button"
                            aria-label={showKeys[name] ? `Hide ${label} key` : `Show ${label} key`}
                            onClick={() => setShowKeys({ ...showKeys, [name]: !showKeys[name] })}
                            style={{ position: 'absolute', right: '10px', top: '10px', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                          >
                            {showKeys[name] ? <EyeOff size={18}/> : <Eye size={18}/>}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div style={{ marginTop: '2rem', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                    {saveStatus && (
                      <span role="status" style={{ fontSize: '0.85rem', color: saveStatus.ok ? 'var(--success)' : 'var(--danger)' }}>{saveStatus.text}</span>
                    )}
                    <button className="gold-button" onClick={handleSaveKeys}>Save API Keys</button>
                  </div>
                </>
              )}
            </div>
          )}

          {/* System */}
          {activeTab === 'system' && (
            <div>
              <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem' }}>System Integration</h2>

              {!desktop ? desktopOnly : (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', padding: '12px 0', borderBottom: '1px solid var(--border)' }}>
                  <div>
                    <div style={{ fontWeight: 500 }}>Launch on Startup</div>
                    <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Start ThreatLens automatically when you log in.</div>
                  </div>
                  <label style={{ position: 'relative', display: 'inline-block', width: '40px', height: '20px', flexShrink: 0 }}>
                    <input
                      type="checkbox"
                      aria-label="Launch on startup"
                      checked={autoLaunch}
                      onChange={(e) => toggleAutoLaunch(e.target.checked)}
                      style={{ opacity: 0, width: 0, height: 0 }}
                    />
                    <span style={{
                      position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0,
                      backgroundColor: autoLaunch ? 'var(--accent-gold)' : 'rgba(255,255,255,0.1)',
                      transition: '.4s', borderRadius: '34px'
                    }}>
                      <span style={{
                        position: 'absolute', height: '16px', width: '16px', left: '2px', bottom: '2px',
                        backgroundColor: 'white', transition: '.4s', borderRadius: '50%',
                        transform: autoLaunch ? 'translateX(20px)' : 'translateX(0)'
                      }}></span>
                    </span>
                  </label>
                </div>
              )}
            </div>
          )}

          {/* About */}
          {activeTab === 'about' && (
            <div style={{ textAlign: 'center', paddingTop: '2rem' }}>
              <Shield size={64} color="var(--accent-gold)" style={{ margin: '0 auto 1rem' }} />
              <h2 style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>Threat<span className="italic-serif" style={{color:'var(--accent-gold)'}}>Lens</span></h2>
              <div style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>Unified Cybersecurity Platform</div>
              {version && <div style={{ color: 'var(--text-muted)' }}>Version {version}</div>}
            </div>
          )}

        </div>
      </div>
    </div>
  );
};

export default Settings;
