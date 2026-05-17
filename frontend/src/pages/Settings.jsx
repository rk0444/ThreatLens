import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Key, Server, Bell, Shield, Power, Info, Eye, EyeOff, Plus, Trash2 } from 'lucide-react';

const Settings = () => {
  const [activeTab, setActiveTab] = useState('keys');
  
  // States for various settings
  const [keys, setKeys] = useState({
    NVD_API_KEY: '', ALIENVAULT_API_KEY: '', ABUSEIPDB_API_KEY: '',
    VIRUSTOTAL_API_KEY: '', OPENAI_API_KEY: '', GROQ_API_KEY: ''
  });
  const [showKeys, setShowKeys] = useState({});
  const [assets, setAssets] = useState([]);
  
  const [notifications, setNotifications] = useState({
    Critical: true, High: true, Medium: false, Low: false, morningBriefTime: '08:00'
  });
  
  const [autoResponse, setAutoResponse] = useState({
    Suspicious: false, Confirmed: true, Critical: true
  });
  
  const [autoLaunch, setAutoLaunch] = useState(false);
  const [appInfo, setAppInfo] = useState({ version: '2.0.0', buildDate: '2026-05-17' });

  useEffect(() => {
    // Load initial data
    if (window.electronAPI) {
      window.electronAPI.readEnv().then(env => {
        setKeys(prev => ({ ...prev, ...env }));
      });
      window.electronAPI.getAppInfo().then(info => setAppInfo(info));
    }
    
    fetch('http://127.0.0.1:8000/api/assets')
      .then(res => res.json())
      .then(data => setAssets(data))
      .catch(e => console.error("Failed to load assets", e));
      
    // Load local storage preferences
    const storedPrefs = localStorage.getItem('threatlens_prefs');
    if (storedPrefs) {
      const prefs = JSON.parse(storedPrefs);
      if (prefs.notifications) setNotifications(prefs.notifications);
      if (prefs.autoResponse) setAutoResponse(prefs.autoResponse);
      if (prefs.autoLaunch !== undefined) setAutoLaunch(prefs.autoLaunch);
    }
  }, []);

  const savePreferences = (key, value) => {
    const prefs = JSON.parse(localStorage.getItem('threatlens_prefs') || '{}');
    prefs[key] = value;
    localStorage.setItem('threatlens_prefs', JSON.stringify(prefs));
  };

  const handleSaveKeys = async () => {
    if (window.electronAPI) {
      await window.electronAPI.writeEnv(keys);
      alert('API Keys saved successfully.');
    }
  };

  const toggleAutoLaunch = async (val) => {
    setAutoLaunch(val);
    savePreferences('autoLaunch', val);
    if (window.electronAPI) {
      await window.electronAPI.toggleAutoLaunch(val);
    }
  };

  const handleDeleteAsset = async (id) => {
    if (confirm('Are you sure you want to delete this asset?')) {
      // Assuming a DELETE endpoint exists, otherwise just local UI update for demo
      try {
        await fetch(`http://127.0.0.1:8000/api/assets/${id}`, { method: 'DELETE' });
        setAssets(assets.filter(a => a.id !== id));
      } catch (e) {
        console.error(e);
      }
    }
  };

  const tabs = [
    { id: 'keys', label: 'API Keys', icon: <Key size={18} /> },
    { id: 'assets', label: 'Asset Management', icon: <Server size={18} /> },
    { id: 'notifications', label: 'Notifications', icon: <Bell size={18} /> },
    { id: 'auto', label: 'Auto-Response', icon: <Shield size={18} /> },
    { id: 'system', label: 'System', icon: <Power size={18} /> },
    { id: 'about', label: 'About', icon: <Info size={18} /> }
  ];

  return (
    <div className="page-container" style={{ padding: '24px' }}>
      <div className="label-small">Configuration</div>
      <h1 style={{ marginBottom: '2rem' }}>System <span className="italic-serif" style={{color: 'var(--accent-gold)'}}>Settings</span></h1>
      
      <div style={{ display: 'grid', gridTemplateColumns: '250px 1fr', gap: '2rem', alignItems: 'start' }}>
        
        {/* Sidebar Tabs */}
        <div className="glass-panel" style={{ padding: '1rem' }}>
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
        <div className="glass-panel" style={{ padding: '2rem', minHeight: '500px' }}>
          
          {/* API Keys */}
          {activeTab === 'keys' && (
            <div>
              <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem' }}>API Keys</h2>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '2rem' }}>Manage your external integrations. Keys are stored locally.</p>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                {Object.keys(keys).map(key => (
                  <div key={key}>
                    <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem' }}>{key.replace(/_/g, ' ')}</label>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <div style={{ position: 'relative', flex: 1 }}>
                        <input
                          type={showKeys[key] ? "text" : "password"}
                          value={keys[key]}
                          onChange={(e) => setKeys({...keys, [key]: e.target.value})}
                          style={{
                            width: '100%', padding: '10px', paddingRight: '40px', borderRadius: '4px',
                            background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', color: 'var(--text-primary)'
                          }}
                        />
                        <button
                          onClick={() => setShowKeys({...showKeys, [key]: !showKeys[key]})}
                          style={{ position: 'absolute', right: '10px', top: '10px', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                        >
                          {showKeys[key] ? <EyeOff size={18}/> : <Eye size={18}/>}
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: '2rem', textAlign: 'right' }}>
                <button className="gold-button" onClick={handleSaveKeys}>Save API Keys</button>
              </div>
            </div>
          )}

          {/* Asset Management */}
          {activeTab === 'assets' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                <h2 style={{ fontSize: '1.5rem' }}>Asset Management</h2>
                <button className="gold-button" style={{ display: 'flex', alignItems: 'center', gap: '4px', padding: '6px 12px', fontSize: '0.9rem' }}>
                  <Plus size={16}/> Add Asset
                </button>
              </div>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {assets.map(asset => (
                  <div key={asset.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '6px' }}>
                    <div>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>{asset.name}</div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{asset.os} &bull; {asset.ip_address}</div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                      <span style={{ fontSize: '0.8rem', color: asset.status === 'Online' ? 'var(--success)' : 'var(--text-muted)' }}>{asset.status}</span>
                      <button onClick={() => handleDeleteAsset(asset.id)} style={{ background: 'none', border: 'none', color: 'var(--danger)', cursor: 'pointer', padding: '4px' }}>
                        <Trash2 size={16}/>
                      </button>
                    </div>
                  </div>
                ))}
                {assets.length === 0 && <div style={{ color: 'var(--text-muted)' }}>No assets registered.</div>}
              </div>
            </div>
          )}

          {/* Notifications */}
          {activeTab === 'notifications' && (
            <div>
              <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem' }}>Notification Preferences</h2>
              
              <div style={{ marginBottom: '2rem' }}>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem' }}>Desktop Alerts</h3>
                {['Critical', 'High', 'Medium', 'Low'].map(level => (
                  <div key={level} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--border)' }}>
                    <span>{level} Severity Alerts</span>
                    <label style={{ position: 'relative', display: 'inline-block', width: '40px', height: '20px' }}>
                      <input 
                        type="checkbox" 
                        checked={notifications[level]}
                        onChange={(e) => {
                          const newNotifs = {...notifications, [level]: e.target.checked};
                          setNotifications(newNotifs);
                          savePreferences('notifications', newNotifs);
                        }}
                        style={{ opacity: 0, width: 0, height: 0 }} 
                      />
                      <span style={{
                        position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0,
                        backgroundColor: notifications[level] ? 'var(--accent-gold)' : 'rgba(255,255,255,0.1)',
                        transition: '.4s', borderRadius: '34px'
                      }}>
                        <span style={{
                          position: 'absolute', content: '""', height: '16px', width: '16px', left: '2px', bottom: '2px',
                          backgroundColor: 'white', transition: '.4s', borderRadius: '50%',
                          transform: notifications[level] ? 'translateX(20px)' : 'translateX(0)'
                        }}></span>
                      </span>
                    </label>
                  </div>
                ))}
              </div>

              <div>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem' }}>Morning Brief</h3>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <span>Delivery Time (UTC)</span>
                  <input 
                    type="time" 
                    value={notifications.morningBriefTime}
                    onChange={(e) => {
                      const newNotifs = {...notifications, morningBriefTime: e.target.value};
                      setNotifications(newNotifs);
                      savePreferences('notifications', newNotifs);
                    }}
                    style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', color: 'var(--text-primary)', padding: '8px', borderRadius: '4px' }}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Auto-Response */}
          {activeTab === 'auto' && (
            <div>
              <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem' }}>Auto-Response Rules</h2>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '2rem' }}>Configure platform behavior for detected threats without manual intervention.</p>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                {Object.keys(autoResponse).map(tier => (
                  <div key={tier} style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '6px', padding: '1rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{tier} Threats</span>
                      <label style={{ position: 'relative', display: 'inline-block', width: '40px', height: '20px' }}>
                        <input 
                          type="checkbox" 
                          checked={autoResponse[tier]}
                          onChange={(e) => {
                            const newRules = {...autoResponse, [tier]: e.target.checked};
                            setAutoResponse(newRules);
                            savePreferences('autoResponse', newRules);
                          }}
                          style={{ opacity: 0, width: 0, height: 0 }} 
                        />
                        <span style={{
                          position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0,
                          backgroundColor: autoResponse[tier] ? 'var(--accent-gold)' : 'rgba(255,255,255,0.1)',
                          transition: '.4s', borderRadius: '34px'
                        }}>
                          <span style={{
                            position: 'absolute', content: '""', height: '16px', width: '16px', left: '2px', bottom: '2px',
                            backgroundColor: 'white', transition: '.4s', borderRadius: '50%',
                            transform: autoResponse[tier] ? 'translateX(20px)' : 'translateX(0)'
                          }}></span>
                        </span>
                      </label>
                    </div>
                    <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                      {tier === 'Suspicious' && 'Isolate network connections but keep processes running pending review.'}
                      {tier === 'Confirmed' && 'Kill malicious processes and quarantine executable files immediately.'}
                      {tier === 'Critical' && 'Full endpoint isolation, capture memory dump, and execute ransomware rollback.'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* System */}
          {activeTab === 'system' && (
            <div>
              <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem' }}>System Integration</h2>
              
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--border)' }}>
                <div>
                  <div style={{ fontWeight: 500 }}>Launch on Startup</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Start ThreatLens automatically when you log in.</div>
                </div>
                <label style={{ position: 'relative', display: 'inline-block', width: '40px', height: '20px' }}>
                  <input 
                    type="checkbox" 
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
                      position: 'absolute', content: '""', height: '16px', width: '16px', left: '2px', bottom: '2px',
                      backgroundColor: 'white', transition: '.4s', borderRadius: '50%',
                      transform: autoLaunch ? 'translateX(20px)' : 'translateX(0)'
                    }}></span>
                  </span>
                </label>
              </div>
            </div>
          )}

          {/* About */}
          {activeTab === 'about' && (
            <div style={{ textAlign: 'center', paddingTop: '2rem' }}>
              <Shield size={64} color="var(--accent-gold)" style={{ margin: '0 auto 1rem' }} />
              <h2 style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>Threat<span className="italic-serif" style={{color:'var(--accent-gold)'}}>Lens</span></h2>
              <div style={{ color: 'var(--text-secondary)', marginBottom: '2rem' }}>Unified Cybersecurity Platform</div>
              
              <div style={{ display: 'inline-flex', flexDirection: 'column', gap: '0.5rem', textAlign: 'left', background: 'rgba(255,255,255,0.02)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
                <div><strong style={{ color: 'var(--text-primary)' }}>Version:</strong> {appInfo.version}</div>
                <div><strong style={{ color: 'var(--text-primary)' }}>Build Date:</strong> {appInfo.buildDate}</div>
                <div><strong style={{ color: 'var(--text-primary)' }}>License:</strong> Enterprise Edition</div>
                <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border)' }}>
                  <a href="#" style={{ color: 'var(--info)', textDecoration: 'none' }}>View on GitHub</a>
                </div>
              </div>
            </div>
          )}
          
        </div>
      </div>
    </div>
  );
};

export default Settings;
