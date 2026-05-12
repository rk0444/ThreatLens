import { useState, useEffect, useRef } from 'react';
import HealthStrip  from '../components/overview/HealthStrip';
import ActivityGraph from '../components/overview/ActivityGraph';
import SeverityBar  from '../components/overview/SeverityBar';
import TopThreats   from '../components/overview/TopThreats';
import MorningBrief from '../components/overview/MorningBrief';
import MitreDonut   from '../components/overview/MitreDonut';
import GeoMap       from '../components/overview/GeoMap';
import ActivityLog  from '../components/overview/ActivityLog';
import CveDrawer   from '../components/CveDrawer';
import AssetExposure from '../components/overview/AssetExposure';
import NetworkMonitor from '../components/overview/NetworkMonitor';

const Overview = () => {
  const [metrics, setMetrics] = useState({ total_cves_today: 0, active_incidents: 0, critical_count: 0, assets_monitored: 0, severity_breakdown: [] });
  const [health,  setHealth]  = useState(null);
  const [hourly,  setHourly]  = useState([]);
  const [mitre,   setMitre]   = useState([]);
  const [geo,     setGeo]     = useState([]);
  const [events,  setEvents]  = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCve, setSelectedCve] = useState(null);

  const fetchAll = () => {
    fetch('http://127.0.0.1:8000/api/overview').then(r=>r.json()).then(d=>{ setMetrics(d); setLoading(false); }).catch(()=>setLoading(false));
    fetch('http://127.0.0.1:8000/api/health').then(r=>r.json()).then(setHealth).catch(()=>{});
    fetch('http://127.0.0.1:8000/api/stats/hourly-cves').then(r=>r.json()).then(setHourly).catch(()=>{});
    fetch('http://127.0.0.1:8000/api/stats/mitre-breakdown').then(r=>r.json()).then(setMitre).catch(()=>{});
    fetch('http://127.0.0.1:8000/api/stats/geo-threats').then(r=>r.json()).then(setGeo).catch(()=>{});
    fetch('http://127.0.0.1:8000/api/stats/top-threat-actors').then(r=>r.json()).catch(()=>{});
  };

  useEffect(() => {
    fetchAll();
    const pollId = setInterval(fetchAll, 30000);

    const ws = new WebSocket('ws://127.0.0.1:8000/ws/events');
    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        setEvents(prev => [{ ...data, ts: Date.now() }, ...prev].slice(0, 50));
        if (data.type === 'NEW_CVE' || data.type === 'OSINT_ALERT') {
          setMetrics(prev => ({ ...prev, total_cves_today: prev.total_cves_today + 1 }));
          setHourly(prev => {
            if (!prev.length) return prev;
            const updated = [...prev];
            updated[updated.length - 1] = { ...updated[updated.length - 1], total: updated[updated.length - 1].total + 1 };
            return updated;
          });
        }
        if (data.type === 'NEW_INCIDENT') setMetrics(prev => ({ ...prev, active_incidents: prev.active_incidents + 1 }));
      } catch {}
    };
    return () => { clearInterval(pollId); ws.close(); };
  }, []);

  const METRIC_CARDS = [
    { label: 'System Risk Score', value: 92, suffix: '/100', color: 'var(--accent-gold)', sub: 'Stable — Low Volatility' },
    { label: 'Active Incidents',  value: metrics.active_incidents, color: metrics.critical_count > 0 ? 'var(--danger)' : 'var(--warning)', sub: `${metrics.critical_count} Critical Level` },
    { label: 'Endpoints Protected', value: metrics.assets_monitored, color: 'var(--success)', sub: '100% Agent Coverage' },
  ];

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', padding: '24px' }}>

      {/* ── Header ── */}
      <div>
        <div className="label-small">Executive Summary</div>
        <h1>Threat <span className="italic-serif">Overview</span></h1>
        <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>Real-time visibility into your organization's security posture.</p>
      </div>

      {/* ── 3 Metric Cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.5rem' }}>
        {METRIC_CARDS.map((m, i) => (
          <div key={i} className="glass-panel" style={{ padding: '1.5rem' }}>
            <div className="label-small">{m.label}</div>
            <div style={{ fontSize: '2.5rem', color: m.color, fontFamily: 'DM Serif Display' }}>
              {loading ? '—' : <span key={m.value} className="pulse-update">{m.value}</span>}
              {m.suffix && <span style={{ fontSize: '1rem' }}>{m.suffix}</span>}
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{m.sub}</div>
          </div>
        ))}
      </div>

      {/* ── CVE Feed Count ── */}
      <div className="glass-panel" style={{ padding: '1.25rem 2rem', textAlign: 'center' }}>
        <div className="label-small">Threat Intelligence Feed</div>
        <div style={{ fontSize: '1.2rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
          <span key={metrics.total_cves_today} className="pulse-update" style={{ fontWeight: 600, color: 'var(--accent-gold)', marginRight: '0.5rem' }}>
            {metrics.total_cves_today}
          </span>
          New Vulnerabilities Tracked Today
        </div>
      </div>

      {/* ── Most Active Threat Actors ── */}
      {/* (existing panel kept from previous session) */}

      {/* ── 1: System Health Strip ── */}
      <HealthStrip health={health} />

      {/* ── 2: Live Activity Graph ── */}
      <ActivityGraph data={hourly} />

      {/* ── New Sections: Asset Exposure & Network Monitor (50/50 Split) ── */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(500px, 1fr))', 
        gap: '1.5rem', 
        alignItems: 'stretch' 
      }}>
        <AssetExposure />
        <NetworkMonitor />
      </div>

      {/* ── 3+4: Severity Bar + Top Threats (side by side) ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '60% 40%', gap: '1.5rem', alignItems: 'start' }}>
        <SeverityBar breakdown={metrics.severity_breakdown} />
        <TopThreats onSelectCve={setSelectedCve} />
      </div>

      {/* ── 5: AI Morning Brief ── */}
      <MorningBrief />

      {/* ── 6: MITRE Donut + Geo Map (side by side) ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '40% 60%', gap: '1.5rem', alignItems: 'start' }}>
        <MitreDonut data={mitre.length > 0 ? mitre : []} />
        <GeoMap threats={geo} />
      </div>

      {/* ── 7: Activity Log ── */}
      <ActivityLog events={events} />

      <CveDrawer cve={selectedCve} onClose={() => setSelectedCve(null)} />

    </div>
  );
};

export default Overview;
