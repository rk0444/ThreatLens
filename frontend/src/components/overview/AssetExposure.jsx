import { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip } from 'recharts';
import { Shield, ShieldAlert, Monitor, ArrowRight, Laptop } from 'lucide-react';

export default function AssetExposure() {
  const [stats, setStats] = useState({ total_cves: 0, affecting_your_assets: 0, exposure_score: 0, most_exposed_asset: { name: 'N/A', count: 0 } });

  const [detail, setDetail] = useState([]);
  const [loading, setLoading] = useState(true);
  const [autoFilter, setAutoFilter] = useState(() => localStorage.getItem('assetAwareFilter') === 'true');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [sRes, dRes] = await Promise.all([
          fetch('http://127.0.0.1:8000/api/stats/asset-exposure'),
          fetch('http://127.0.0.1:8000/api/assets/exposure-detail')
        ]);
        setStats(await sRes.json());
        setDetail(await dRes.json());
        setLoading(false);
      } catch (e) {
        console.error(e);
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleToggle = (val) => {
    setAutoFilter(val);
    localStorage.setItem('assetAwareFilter', val);
  };

  if (loading) return <div className="glass-panel skeleton" style={{ height: '500px' }} />;

  if (!detail.length) {
    return (
      <div className="glass-panel" style={{ height: '500px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', padding: '2rem' }}>
        <Monitor size={48} color="var(--text-muted)" style={{ marginBottom: '1rem' }} />
        <div className="label-small">ASSET EXPOSURE</div>
        <h2 style={{ marginBottom: '1rem' }}>No assets registered</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '2rem', maxWidth: '300px' }}>
          Add your machines to see which specific CVEs affect your technology stack.
        </p>
        <button className="gold-button">Add Asset</button>
      </div>
    );
  }

  const chartData = [
    { name: 'Affecting You', value: stats.affecting_your_assets, color: 'var(--danger)' },
    { name: 'Not Relevant', value: stats.total_cves - stats.affecting_your_assets, color: 'var(--bg-surface)' }
  ];

  const scoreColor = stats.exposure_score > 50 ? 'var(--danger)' : stats.exposure_score > 25 ? 'var(--warning)' : 'var(--success)';

  return (
    <div className="glass-panel" style={{ padding: '20px', height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div className="label-small">ASSET EXPOSURE</div>
      <h2 style={{ marginBottom: '1.5rem' }}>Your Asset Attack Surface</h2>

      {/* Exposure Summary Bar */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', padding: '1rem', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', marginBottom: '2rem' }}>
        <div>
          <div className="label-small" style={{ fontSize: '9px' }}>CVEs TARGETING ASSETS</div>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--accent-gold)' }}>{stats.affecting_your_assets}</div>
        </div>
        <div style={{ borderLeft: '1px solid var(--border)', borderRight: '1px solid var(--border)', padding: '0 1rem' }}>
          <div className="label-small" style={{ fontSize: '9px' }}>YOUR EXPOSURE SCORE</div>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, color: scoreColor }}>{stats.exposure_score}%</div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>critical/high impact</div>
        </div>
        <div style={{ paddingLeft: '1rem' }}>
          <div className="label-small" style={{ fontSize: '9px' }}>MOST EXPOSED ASSET</div>
          <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-gold)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {stats.most_exposed_asset.name}
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{stats.most_exposed_asset.count} vulnerabilities</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2rem' }}>
        <div style={{ width: '160px', height: '160px', position: 'relative' }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={chartData} innerRadius={55} outerRadius={75} paddingAngle={5} dataKey="value" stroke="none">
                {chartData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center', pointerEvents: 'none' }}>
            <div style={{ fontSize: '1.2rem', fontWeight: 700 }}>{stats.affecting_your_assets}</div>
            <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', lineHeight: 1 }}>OF {stats.total_cves}<br/>AFFECT YOU</div>
          </div>
        </div>
        <div style={{ flex: 1, paddingLeft: '2rem' }}>
           {chartData.map(item => (
             <div key={item.name} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <div style={{ width: 8, height: 8, borderRadius: '2px', background: item.color }} />
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{item.name}:</span>
                <span style={{ fontSize: '0.8rem', fontWeight: 700 }}>{item.value} ({((item.value / stats.total_cves) * 100).toFixed(1)}%)</span>
             </div>
           ))}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', marginBottom: '1.5rem' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
              <th style={{ padding: '8px 0', color: 'var(--text-muted)' }}>ASSET</th>
              <th style={{ padding: '8px 0', color: 'var(--text-muted)', textAlign: 'center' }}>CVEs</th>
              <th style={{ padding: '8px 0', color: 'var(--text-muted)' }}>HIGHEST RISK</th>
              <th style={{ padding: '8px 0', color: 'var(--text-muted)' }}>ACTION</th>
            </tr>
          </thead>
          <tbody>
            {detail.map(asset => (
              <tr key={asset.hostname} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                <td style={{ padding: '10px 0' }}>
                  <div style={{ fontWeight: 600 }}>{asset.hostname}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{asset.os}</div>
                </td>
                <td style={{ textAlign: 'center', fontWeight: 700, color: asset.affecting_cves > 0 ? 'var(--danger)' : 'var(--success)' }}>
                  {asset.affecting_cves}
                </td>
                <td>
                  {asset.highest_risk_cve ? (
                    <div>
                      <div style={{ color: 'var(--accent-gold)', fontFamily: 'JetBrains Mono' }}>{asset.highest_risk_cve.id}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>via {asset.most_vulnerable_package}</div>
                    </div>
                  ) : '—'}
                </td>
                <td>
                  <button 
                    onClick={() => window.location.href = `/global-threats?asset=${asset.hostname}`}
                    style={{ background: 'none', border: '1px solid var(--border)', borderRadius: '4px', color: 'var(--text-secondary)', padding: '2px 8px', fontSize: '0.7rem', cursor: 'pointer' }}
                  >
                    View CVEs
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ borderTop: '1px solid var(--border)', paddingTop: '1rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
          <div style={{ position: 'relative', width: '32px', height: '18px', background: autoFilter ? 'var(--accent-gold)' : 'var(--bg-surface)', borderRadius: '10px', transition: '0.3s' }}>
             <input 
              type="checkbox" checked={autoFilter} onChange={e => handleToggle(e.target.checked)}
              style={{ opacity: 0, width: '100%', height: '100%', cursor: 'pointer', position: 'absolute', zIndex: 2 }}
             />
             <div style={{ position: 'absolute', top: '2px', left: autoFilter ? '16px' : '2px', width: '14px', height: '14px', background: 'white', borderRadius: '50%', transition: '0.3s' }} />
          </div>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: autoFilter ? 'var(--accent-gold)' : 'var(--text-secondary)' }}>
            Show only my assets' CVEs in Global Threats
          </span>
        </label>
      </div>
    </div>
  );
}
