import { useState, useEffect, useCallback } from 'react';
import { Plus, X, Monitor, AlertTriangle, Clock, Trash2 } from 'lucide-react';
import CustomDropdown from '../components/CustomDropdown';
import { useWebSocket } from '../hooks/useWebSocket';
import { getRiskColor } from '../utils/riskScore';

const API = 'http://127.0.0.1:8000';
const REFRESH_EVENTS = ['ASSET_ADDED', 'ASSET_DELETED', 'NEW_INCIDENT', 'INCIDENT_UPDATE'];
const EMPTY_FORM = { name: '', os: 'Windows 11 Pro', ip_address: '', software_list: '' };

const OS_BADGES = {
  'Windows 11': { color: '#0078d4', label: 'WIN 11' },
  'Windows 10': { color: '#005a9e', label: 'WIN 10' },
  'Windows 7':  { color: '#003a6e', label: 'WIN 7' },
  'Server':     { color: '#004578', label: 'SERVER' },
  'Ubuntu':     { color: '#e95420', label: 'UBUNTU' },
  'Debian':     { color: '#a80030', label: 'DEBIAN' },
  'CentOS':     { color: '#932279', label: 'CENTOS' },
  'macOS':      { color: '#555', label: 'macOS' },
};

const getOsBadge = (os = '') => {
  for (const [key, val] of Object.entries(OS_BADGES)) {
    if (os.includes(key)) return val;
  }
  return { color: '#444', label: 'OTHER' };
};

// Online/offline comes from the server (agent heartbeat within the last minute); this only words the last check-in
const getCheckinLabel = (lastSeen, online, now) => {
  if (!lastSeen) return { text: 'Never', color: 'var(--danger)', warn: true };
  if (online) return { text: 'Just now', color: 'var(--success)' };
  const mins = Math.floor((now - new Date(lastSeen).getTime()) / 60000);
  if (mins < 60)   return { text: `${mins}m ago`, color: 'var(--warning)', warn: true };
  if (mins < 1440) return { text: `${Math.floor(mins / 60)}h ago`, color: 'var(--warning)', warn: true };
  return { text: `${new Date(lastSeen).toLocaleDateString()} (no agent reporting)`, color: 'var(--danger)', warn: true };
};

const statusOf = (asset) => asset.online
  ? { label: 'Online', color: 'var(--success)' }
  : { label: 'Offline', color: 'var(--danger)' };

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
  const [selected, setSelected]     = useState(null);
  const [assetIncs, setAssetIncs]   = useState([]);
  const [showModal, setShowModal]   = useState(false);
  const [form, setForm]             = useState(EMPTY_FORM);
  const [formError, setFormError]   = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [now, setNow]               = useState(() => Date.now());

  const fetchAssets = useCallback(() =>
    getJson(`${API}/api/assets`)
      .then(d => { setAssets(d); setError(null); setNow(Date.now()); })
      .catch(e => setError(`Could not load endpoints (${e.message}). Is the backend running?`))
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

  const openDetail = (asset) => {
    setSelected(asset);
    setAssetIncs([]);
    getJson(`${API}/api/assets/${asset.id}/incidents`).then(setAssetIncs).catch(() => setAssetIncs([]));
  };

  const handleAdd = async () => {
    setSubmitting(true);
    setFormError(null);
    const payload = { ...form, software_list: form.software_list.split(',').map(s => s.trim()).filter(Boolean) };
    try {
      await getJson(`${API}/api/assets`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      setShowModal(false);
      setForm(EMPTY_FORM);
      fetchAssets();
    } catch (e) {
      setFormError(`Could not register the endpoint (${e.message}).`);
    }
    setSubmitting(false);
  };

  const handleDelete = async (id) => {
    if (confirm('Are you sure you want to remove this endpoint? This will also clear all incidents associated with it.')) {
      try {
        await getJson(`${API}/api/assets/${id}`, { method: 'DELETE' });
        setSelected(null);
        fetchAssets();
      } catch (e) {
        setError(`Could not remove the endpoint (${e.message}).`);
      }
    }
  };

  const onlineCount = assets.filter(a => a.online).length;

  const osOptions = [
    { value: 'Windows 11 Pro', label: 'Windows 11 Pro' },
    { value: 'Windows 10 Pro', label: 'Windows 10 Pro' },
    { value: 'Windows Server 2022', label: 'Windows Server 2022' },
    { value: 'Ubuntu 22.04', label: 'Ubuntu 22.04' },
    { value: 'macOS Ventura', label: 'macOS Ventura' },
    { value: 'Debian 12', label: 'Debian 12' },
    { value: 'CentOS 9', label: 'CentOS 9' },
  ];

  return (
    <div className="page-container" style={{ padding: '24px' }}>
      <style>{`
        .ep-card { border: 1px solid rgba(184,146,42,0.15); transition: border-color 200ms, box-shadow 200ms; min-height: 220px; display: flex; flex-direction: column; padding: 0; overflow: hidden; cursor: pointer; }
        .ep-card:hover { border-color: rgba(184,146,42,0.5) !important; box-shadow: 0 0 16px rgba(184,146,42,0.1) !important; }
        .ep-grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fill, minmax(300px,1fr)); }
        @media(min-width:1400px){.ep-grid{grid-template-columns:repeat(3,1fr)}}
        @media(min-width:900px) and (max-width:1399px){.ep-grid{grid-template-columns:repeat(2,1fr)}}
        @media(max-width:899px){.ep-grid{grid-template-columns:1fr}}
        .pulse-red { animation: pulseCritical 2s infinite; }
      `}</style>

      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-end', marginBottom:'2rem' }}>
        <div>
          <div className="label-small">Agent Protection</div>
          <h1>Endpoint <span className="italic-serif">Protection</span></h1>
          {!loading && !error && (
            <div className="status-badge" style={{ marginTop:'0.5rem', width:'fit-content' }}>
              <span>{onlineCount} / {assets.length} agents reporting</span>
            </div>
          )}
        </div>
        <button className="gold-button" onClick={()=>setShowModal(true)} style={{ display:'flex', alignItems:'center', gap:'0.5rem' }}>
          <Plus size={18}/> Register Endpoint
        </button>
      </div>

      {error && (
        <div role="alert" style={{ marginBottom:'1.5rem', padding:'12px 16px', borderRadius:'6px', border:'1px solid rgba(229,62,62,0.4)', background:'rgba(74,26,26,0.6)', color:'#fc8181' }}>
          {error}
        </div>
      )}

      {/* Stats Row (hidden until loaded, so a failed load never shows zeros as real) */}
      {!loading && !(error && assets.length === 0) && (
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,minmax(0,1fr))', gap:'1rem', marginBottom:'2rem' }}>
        {[
          { label:'Total Endpoints',  value: assets.length,                                        color:'var(--accent-gold)' },
          { label:'Online',           value: onlineCount,                                          color:'var(--success)'     },
          { label:'Offline',          value: assets.length - onlineCount,                          color:'var(--danger)'      },
          { label:'Active Incidents', value: assets.reduce((s,a)=>s+(a.active_incident_count||0),0),color:'var(--warning)'     },
        ].map((s,i) => (
          <div key={i} className="glass-panel" style={{ padding:'1.25rem' }}>
            <div className="label-small">{s.label}</div>
            <div style={{ fontSize:'2rem', fontWeight:700, color:s.color, fontFamily:'DM Serif Display' }}>{s.value}</div>
          </div>
        ))}
      </div>
      )}

      {!loading && !error && assets.length === 0 && (
        <div style={{ textAlign:'center', padding:'80px 0', color:'var(--text-muted)' }}>
          <Monitor size={40} style={{ opacity:0.4, marginBottom:'1rem' }}/>
          <h3 style={{ color:'var(--text-secondary)' }}>No endpoints yet</h3>
          <p style={{ fontSize:'0.9rem' }}>Run the ThreatLens agent on a machine to register it, or use Register Endpoint.</p>
        </div>
      )}

      {/* Card Grid */}
      <div className="ep-grid">
        {loading ? [1,2,3].map(i=><div key={i} className="glass-panel skeleton" style={{height:'220px'}}/>)
        : assets.map(asset => {
          const osBadge     = getOsBadge(asset.os);
          const agentStatus = statusOf(asset);
          const checkin     = getCheckinLabel(asset.last_seen, asset.online, now);
          const top         = asset.top_cve;
          const sw          = asset.software_list || [];
          const swDisplay   = sw.slice(0,2).join(', ') + (sw.length>2 ? ` +${sw.length-2} more` : '');
          const summary     = asset.latest_incident_summary;

          return (
            <div key={asset.id} className="glass-panel ep-card" onClick={() => openDetail(asset)}>

              {/* Top accent strip — color by agent status */}
              <div style={{ height:'3px', background: agentStatus.color, flexShrink:0 }}/>

              {/* ROW 1: Header */}
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', padding:'14px 16px 10px' }}>
                {/* Left: icon + name + OS badge */}
                <div style={{ display:'flex', alignItems:'flex-start', gap:'10px' }}>
                  <Monitor size={26} color={agentStatus.color} style={{ marginTop:'2px', flexShrink:0 }}/>
                  <div>
                    <div style={{ fontWeight:700, fontSize:'1.05rem', color:'var(--text-primary)' }}>{asset.name}</div>
                    <span style={{ background:osBadge.color, color:'white', fontSize:'0.62rem', fontWeight:700, padding:'1px 6px', borderRadius:'3px', letterSpacing:'0.5px', marginTop:'4px', display:'inline-block' }}>
                      {osBadge.label}
                    </span>
                  </div>
                </div>
                {/* Right: status pill */}
                <div style={{ display:'flex', flexDirection:'column', alignItems:'flex-end', gap:'6px' }}>
                  <div style={{ fontSize:'0.7rem', fontWeight:600, color: agentStatus.color, display:'flex', alignItems:'center', gap:'4px' }}>
                    <div style={{ width:'6px', height:'6px', borderRadius:'50%', background: agentStatus.color }}/>
                    {agentStatus.label}
                  </div>
                </div>
              </div>

              {/* DIVIDER */}
              <div style={{ height:'1px', background:'rgba(184,146,42,0.12)', margin:'0 16px' }}/>

              {/* ROW 2: Active incidents + published exposure (CVEs matching this asset's software) */}
              <div style={{ display:'flex', gap:'8px', padding:'10px 16px' }}>
                {[
                  { label:`${asset.active_incident_count||0} Active incident${asset.active_incident_count===1?'':'s'}`, bg: (asset.active_incident_count||0)>0 ? 'rgba(229,62,62,0.15)'  : 'rgba(255,255,255,0.04)', border: (asset.active_incident_count||0)>0 ? 'rgba(229,62,62,0.4)'    : 'rgba(255,255,255,0.08)', color: (asset.active_incident_count||0)>0 ? '#fc8181' : 'var(--text-muted)' },
                  { label: sw.length === 0 ? 'No software listed' : top ? `${asset.matching_cve_count} CVEs · top ${top.risk_score} ${top.risk_band}` : '0 matching CVEs',
                    bg:'rgba(255,255,255,0.04)', border:'rgba(255,255,255,0.08)', color: top ? getRiskColor(top.risk_score) : 'var(--text-muted)' },
                ].map((p,i) => (
                  <div key={i} style={{ flex:1, textAlign:'center', padding:'4px 0', background:p.bg, border:`1px solid ${p.border}`, borderRadius:'4px', fontSize:'0.68rem', fontWeight:600, color:p.color }}>
                    {p.label}
                  </div>
                ))}
              </div>

              {/* DIVIDER */}
              <div style={{ height:'1px', background:'rgba(184,146,42,0.12)', margin:'0 16px' }}/>

              {/* ROW 3: Info rows */}
              <div style={{ padding:'10px 16px', display:'flex', flexDirection:'column', gap:'7px', flex:1 }}>
                <div style={{ display:'flex', justifyContent:'space-between', fontSize:'0.83rem' }}>
                  <span style={{ color:'var(--text-muted)' }}>IP Address</span>
                  <span style={{ fontFamily:'JetBrains Mono', color:'var(--text-secondary)' }}>{asset.ip_address}</span>
                </div>
                <div style={{ display:'flex', justifyContent:'space-between', fontSize:'0.83rem' }}>
                  <span style={{ color:'var(--text-muted)', display:'flex', alignItems:'center', gap:'4px' }}>
                    <Clock size={12}/> Last Check-In
                  </span>
                  <span style={{ display:'flex', alignItems:'center', gap:'4px', color: checkin.color }}>
                    {checkin.warn && <AlertTriangle size={12}/>}
                    {checkin.text}
                  </span>
                </div>
                <div style={{ display:'flex', justifyContent:'space-between', fontSize:'0.83rem' }}>
                  <span style={{ color:'var(--text-muted)' }}>Software</span>
                  <span style={{ color:'var(--text-secondary)', textAlign:'right', maxWidth:'180px', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                    {swDisplay || <span style={{color:'var(--text-muted)'}}>None listed</span>}
                  </span>
                </div>
              </div>

              {/* DIVIDER */}
              <div style={{ height:'1px', background:'rgba(184,146,42,0.15)' }}/>

              {/* ROW 4: Bottom bar — latest incident + View Details */}
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'9px 16px' }}>
                <div style={{ fontSize:'0.75rem', color: summary ? 'var(--text-muted)' : 'var(--success)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', maxWidth:'65%' }}>
                  {summary ? summary.slice(0,35) + (summary.length>35?'…':'') : 'No incidents detected'}
                </div>
                <span style={{ fontSize:'0.78rem', color:'var(--accent-gold)', fontWeight:600, flexShrink:0 }}>View Details ›</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Detail Drawer */}
      {selected && (
        <div className="drawer-overlay" onClick={()=>setSelected(null)}>
          <div className="drawer" onClick={e=>e.stopPropagation()}>
            <div className="drawer-header">
              <div>
                <div className="label-small">{selected.ip_address}</div>
                <h2>{selected.name}</h2>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button 
                  className="close-btn" 
                  onClick={() => handleDelete(selected.id)} 
                  title="Remove Endpoint"
                  style={{ color: 'var(--danger)' }}
                >
                  <Trash2 size={20} />
                </button>
                <button className="close-btn" onClick={() => setSelected(null)}>
                  <X size={24} />
                </button>
              </div>
            </div>
            <div className="drawer-content">
              <div className="info-grid">
                <div className="info-item"><span className="label-small">OS</span><div className="value">{selected.os}</div></div>
                <div className="info-item"><span className="label-small">IP</span><div className="value" style={{fontFamily:'JetBrains Mono'}}>{selected.ip_address}</div></div>
                <div className="info-item"><span className="label-small">Matching CVEs</span><div className="value">{(selected.software_list||[]).length ? selected.matching_cve_count : 'No software listed'}</div></div>
                <div className="info-item"><span className="label-small">Highest CVE Risk</span><div className="value" style={{color: selected.top_cve ? getRiskColor(selected.top_cve.risk_score) : 'var(--text-muted)'}}>{selected.top_cve ? `${selected.top_cve.risk_score} ${selected.top_cve.risk_band} (${selected.top_cve.cve_id})` : '—'}</div></div>
                <div className="info-item"><span className="label-small">Active Incidents</span><div className="value">{selected.active_incident_count||0}</div></div>
              </div>
              <div className="asset-section" style={{marginTop:'2rem'}}>
                <div className="label-small">Installed Software ({(selected.software_list||[]).length})</div>
                <div style={{display:'flex',flexWrap:'wrap',gap:'0.5rem',marginTop:'0.75rem'}}>
                  {(selected.software_list||[]).map((pkg,i)=>(
                    <span key={i} style={{background:'rgba(255,255,255,0.05)',border:'1px solid var(--border)',padding:'0.25rem 0.6rem',borderRadius:'4px',fontSize:'0.8rem',color:'var(--text-secondary)'}}>{pkg}</span>
                  ))}
                </div>
              </div>
              <div className="asset-section" style={{marginTop:'2rem'}}>
                <div className="label-small">Recent Incidents ({assetIncs.length})</div>
                {assetIncs.length===0
                  ? <p style={{color:'var(--text-muted)',marginTop:'0.5rem'}}>No incidents on this endpoint.</p>
                  : <div style={{display:'flex',flexDirection:'column',gap:'0.75rem',marginTop:'0.75rem'}}>
                      {assetIncs.slice(0,5).map(inc=>(
                        <div key={inc.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',background:'rgba(255,255,255,0.02)',padding:'0.75rem',borderRadius:'4px',border:'1px solid var(--border)'}}>
                          <div>
                            <div style={{fontWeight:600,fontSize:'0.9rem'}}>{inc.type}</div>
                            <div style={{color:'var(--text-muted)',fontSize:'0.75rem',marginTop:'0.2rem'}}>{new Date(inc.created_at).toLocaleString()}</div>
                          </div>
                          <span className={`severity-badge severity-${inc.severity?.toLowerCase()}`}>{inc.severity}</span>
                        </div>
                      ))}
                    </div>
                }
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Endpoint Modal */}
      {showModal && (
        <div className="drawer-overlay" onClick={()=>setShowModal(false)}>
          <div style={{background:'var(--surface)',border:'1px solid var(--border)',borderRadius:'8px',padding:'2rem',width:'480px',maxWidth:'90vw', overflow:'visible'}} onClick={e=>e.stopPropagation()}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'2rem'}}>
              <h2 style={{margin:0}}>Register Endpoint</h2>
              <button className="close-btn" onClick={()=>setShowModal(false)}><X/></button>
            </div>
            <div style={{display:'flex',flexDirection:'column',gap:'1.25rem'}}>
              {[{label:'Hostname',key:'name',ph:'e.g. WS-DEV-02'},{label:'IP Address',key:'ip_address',ph:'e.g. 192.168.1.52'},{label:'Software (comma-separated)',key:'software_list',ph:'Chrome, VS Code, Python'}].map(({label,key,ph})=>(
                <div key={key}>
                  <div className="label-small" style={{marginBottom:'0.4rem'}}>{label}</div>
                  <input type="text" value={form[key]} onChange={e=>setForm({...form,[key]:e.target.value})} placeholder={ph}
                    style={{width:'100%',background:'rgba(255,255,255,0.05)',border:'1px solid var(--border)',borderRadius:'4px',padding:'0.6rem 0.8rem',color:'var(--text-primary)',fontSize:'0.9rem',boxSizing:'border-box'}}/>
                </div>
              ))}
              <div>
                <div className="label-small" style={{marginBottom:'0.4rem'}}>Operating System</div>
                <CustomDropdown 
                  options={osOptions}
                  value={form.os}
                  onChange={(val) => setForm({...form, os: val})}
                />
              </div>
            </div>
            {formError && <div role="alert" style={{ color:'var(--danger)', fontSize:'0.85rem', marginTop:'1rem' }}>{formError}</div>}
            <button className="gold-button" style={{width:'100%',marginTop:'2rem'}} onClick={handleAdd} disabled={submitting||!form.name||!form.ip_address}>
              {submitting?'Registering...':'Register Endpoint'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
