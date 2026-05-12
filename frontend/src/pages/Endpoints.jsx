import { useState, useEffect } from 'react';
import { Plus, X, Monitor, AlertTriangle, Clock } from 'lucide-react';
import CustomDropdown from '../components/CustomDropdown';

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

const getAgentStatus = (lastSeen) => {
  if (!lastSeen) return { label: 'Offline', color: 'var(--danger)' };
  const secs = (Date.now() - new Date(lastSeen).getTime()) / 1000;
  if (secs < 60)    return { label: 'Online', color: 'var(--success)' };
  if (secs < 300)   return { label: 'Idle',   color: 'var(--warning)' };
  if (secs < 3600)  return { label: 'Stale',  color: '#f6ad55' };
  return              { label: 'Offline', color: 'var(--danger)' };
};

const getCheckinLabel = (lastSeen) => {
  if (!lastSeen) return { text: 'Never', color: 'var(--danger)' };
  const secs = (Date.now() - new Date(lastSeen).getTime()) / 1000;
  if (secs < 60)   return { text: 'Just now',                          color: 'var(--success)' };
  if (secs < 300)  return { text: `${Math.floor(secs/60)}m ago`,       color: 'var(--success)' };
  if (secs < 3600) return { text: `${Math.floor(secs/60)}m ago`,       color: 'var(--warning)', warn: true };
  if (secs < 86400)return { text: `${Math.floor(secs/3600)}h ago`,     color: '#f6ad55', warn: true };
  return             { text: 'Agent may be down',                       color: 'var(--danger)', warn: true };
};

const getRiskColor = (score) => {
  if (score >= 86) return 'var(--danger)';
  if (score >= 61) return '#fc8181';
  if (score >= 31) return 'var(--warning)';
  return 'var(--success)';
};

export default function Endpoints() {
  const [assets, setAssets]         = useState([]);
  const [loading, setLoading]       = useState(true);
  const [selected, setSelected]     = useState(null);
  const [assetIncs, setAssetIncs]   = useState([]);
  const [showModal, setShowModal]   = useState(false);
  const [form, setForm]             = useState({ name: '', os: 'Windows 11 Pro', ip_address: '', software_list: '', status: 'Online' });
  const [submitting, setSubmitting] = useState(false);

  const fetchAssets = () =>
    fetch('http://127.0.0.1:8000/api/assets')
      .then(r => r.json()).then(d => { setAssets(d); setLoading(false); })
      .catch(() => setLoading(false));

  useEffect(() => {
    fetchAssets();
    const ws = new WebSocket('ws://127.0.0.1:8000/ws/events');
    ws.onmessage = e => { if (JSON.parse(e.data).type === 'ASSET_ADDED') fetchAssets(); };
    return () => ws.close();
  }, []);

  const openDetail = (asset) => {
    setSelected(asset);
    fetch(`http://127.0.0.1:8000/api/assets/${asset.id}/incidents`)
      .then(r => r.json()).then(setAssetIncs).catch(() => setAssetIncs([]));
  };

  const handleAdd = async () => {
    setSubmitting(true);
    const payload = { ...form, software_list: form.software_list.split(',').map(s => s.trim()).filter(Boolean) };
    const res = await fetch('http://127.0.0.1:8000/api/assets', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    if (res.ok) { setShowModal(false); setForm({ name: '', os: 'Windows 11 Pro', ip_address: '', software_list: '', status: 'Online' }); fetchAssets(); }
    setSubmitting(false);
  };

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
          <div className="status-badge" style={{ marginTop:'0.5rem', width:'fit-content' }}>
            <div className="status-dot" />
            <span>LIVE — {assets.filter(a=>a.status==='Online').length} / {assets.length} Agents Online</span>
          </div>
        </div>
        <button className="gold-button" onClick={()=>setShowModal(true)} style={{ display:'flex', alignItems:'center', gap:'0.5rem' }}>
          <Plus size={18}/> Register Endpoint
        </button>
      </div>

      {/* Stats Row */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:'1rem', marginBottom:'2rem' }}>
        {[
          { label:'Total Endpoints',  value: assets.length,                                        color:'var(--accent-gold)' },
          { label:'Online',           value: assets.filter(a=>a.status==='Online').length,          color:'var(--success)'     },
          { label:'Offline',          value: assets.filter(a=>a.status==='Offline').length,         color:'var(--danger)'      },
          { label:'Active Incidents', value: assets.reduce((s,a)=>s+(a.active_incident_count||0),0),color:'var(--warning)'     },
        ].map((s,i) => (
          <div key={i} className="glass-panel" style={{ padding:'1.25rem' }}>
            <div className="label-small">{s.label}</div>
            <div style={{ fontSize:'2rem', fontWeight:700, color:s.color, fontFamily:'DM Serif Display' }}>{loading?'—':s.value}</div>
          </div>
        ))}
      </div>

      {/* Card Grid */}
      <div className="ep-grid">
        {loading ? [1,2,3].map(i=><div key={i} className="glass-panel skeleton" style={{height:'220px'}}/>)
        : assets.map(asset => {
          const osBadge     = getOsBadge(asset.os);
          const agentStatus = getAgentStatus(asset.last_seen);
          const checkin     = getCheckinLabel(asset.last_seen);
          const riskScore   = asset.risk_score || 0;
          const riskColor   = getRiskColor(riskScore);
          const isPulsing   = riskScore >= 86;
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
                {/* Right: risk circle + status pill */}
                <div style={{ display:'flex', flexDirection:'column', alignItems:'flex-end', gap:'6px' }}>
                  {/* Risk score circle */}
                  <div style={{ width:'38px', height:'38px', borderRadius:'50%', border:`2px solid ${riskColor}`, display:'flex', alignItems:'center', justifyContent:'center', fontWeight:700, fontSize:'0.8rem', color: riskColor, animation: isPulsing ? 'pulseCritical 2s infinite' : 'none', background:'rgba(0,0,0,0.3)' }}>
                    {riskScore}
                  </div>
                  {/* Status pill */}
                  <div style={{ fontSize:'0.7rem', fontWeight:600, color: agentStatus.color, display:'flex', alignItems:'center', gap:'4px' }}>
                    <div style={{ width:'6px', height:'6px', borderRadius:'50%', background: agentStatus.color }}/>
                    {agentStatus.label}
                  </div>
                </div>
              </div>

              {/* DIVIDER */}
              <div style={{ height:'1px', background:'rgba(184,146,42,0.12)', margin:'0 16px' }}/>

              {/* ROW 2: Incident stat pills */}
              <div style={{ display:'flex', gap:'8px', padding:'10px 16px' }}>
                {[
                  { label:`${asset.active_incident_count||0} Active`,    bg: (asset.active_incident_count||0)>0 ? 'rgba(229,62,62,0.15)'  : 'rgba(255,255,255,0.04)', border: (asset.active_incident_count||0)>0 ? 'rgba(229,62,62,0.4)'    : 'rgba(255,255,255,0.08)', color: (asset.active_incident_count||0)>0 ? '#fc8181' : 'var(--text-muted)' },
                  { label:`${asset.threats_blocked||0} Blocked`,         bg:'rgba(72,187,120,0.1)',                                         border:'rgba(72,187,120,0.3)',                                                                    color:'var(--success)' },
                  { label:`${asset.files_quarantined||0} Quarantined`,   bg:'rgba(236,153,75,0.1)',                                         border:'rgba(236,153,75,0.3)',                                                                    color:'var(--warning)' },
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
              <button className="close-btn" onClick={()=>setSelected(null)}><X/></button>
            </div>
            <div className="drawer-content">
              <div className="info-grid">
                <div className="info-item"><span className="label-small">OS</span><div className="value">{selected.os}</div></div>
                <div className="info-item"><span className="label-small">IP</span><div className="value" style={{fontFamily:'JetBrains Mono'}}>{selected.ip_address}</div></div>
                <div className="info-item"><span className="label-small">Risk Score</span><div className="value" style={{color:getRiskColor(selected.risk_score||0)}}>{selected.risk_score||0}/100</div></div>
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
            <button className="gold-button" style={{width:'100%',marginTop:'2rem'}} onClick={handleAdd} disabled={submitting||!form.name||!form.ip_address}>
              {submitting?'Registering...':'Register Endpoint'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
