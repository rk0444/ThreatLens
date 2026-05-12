import { useState, useEffect } from 'react';

const getSeverityClass = (score) => {
  if (score >= 86) return 'severity-critical';
  if (score >= 61) return 'severity-high';
  if (score >= 31) return 'severity-medium';
  if (score >= 11) return 'severity-low';
  return 'severity-info';
};

const getRiskColor = (score) => {
  if (score >= 86) return 'var(--danger)';
  if (score >= 61) return '#fc8181';
  if (score >= 31) return 'var(--warning)';
  return 'var(--success)';
};

export default function TopThreats({ onSelectCve }) {
  const [cves, setCves] = useState([]);
  const [newIds, setNewIds] = useState(new Set());

  const fetch5 = () => {
    fetch('http://127.0.0.1:8000/api/cves?sort=risk_score&limit=5')
      .then(r => r.json())
      .then(data => {
        if (!Array.isArray(data)) return;
        const sorted = data; // Already sorted by backend
        setCves(prev => {
          const prevIds = new Set(prev.map(c => c.id));
          const added = new Set(sorted.filter(c => !prevIds.has(c.id)).map(c => c.id));
          if (added.size) {
            setNewIds(added);
            setTimeout(() => setNewIds(new Set()), 2500);
          }
          return sorted;
        });
      })
      .catch(() => {});
  };

  useEffect(() => {
    fetch5();
    const id = setInterval(fetch5, 30000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', height: '100%' }}>
      <div className="label-small" style={{ marginBottom: '0.25rem' }}>LIVE RISK RANKING</div>
      <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '1rem' }}>Top Critical Threats</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {cves.length === 0
          ? [1,2,3,4,5].map(i => <div key={i} className="skeleton" style={{ height: '52px', borderRadius: '4px' }} />)
          : cves.map((cve, i) => {
              const risk = Math.round((cve.cvss_score || 0) * 10);
              const color = getRiskColor(risk);
              const isNew = newIds.has(cve.id);
              return (
                <div key={cve.id} onClick={() => onSelectCve?.(cve)}
                  style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 10px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '4px', cursor: 'pointer', animation: isNew ? 'slideInFromTop 0.4s ease' : 'none', transition: 'background 0.2s' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(184,146,42,0.07)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}>
                  <div style={{ width: 36, height: 36, borderRadius: '50%', border: `2px solid ${color}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.72rem', color, flexShrink: 0 }}>
                    {risk}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--accent-gold)', fontSize: '0.82rem', fontWeight: 600 }}>{cve.cve_id}</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {cve.description?.slice(0, 55)}{cve.description?.length > 55 ? '…' : ''}
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '3px', flexShrink: 0 }}>
                    <span className={`severity-badge ${getSeverityClass(risk)}`} style={{ fontSize: '0.6rem' }}>{risk >= 86 ? 'CRITICAL' : risk >= 61 ? 'HIGH' : 'MED'}</span>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>EPSS {((cve.epss_score || 0) * 100).toFixed(1)}%</span>
                  </div>
                </div>
              );
            })}
      </div>
      <style>{`@keyframes slideInFromTop{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}`}</style>
    </div>
  );
}
