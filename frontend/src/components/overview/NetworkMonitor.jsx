import { useState, useEffect } from 'react';
import { Shield, Activity, Globe, Search, Lock, AlertTriangle } from 'lucide-react';

export default function NetworkMonitor() {
  const [stats, setStats] = useState({ connections_monitored_today: 0, flagged_today: 0, blocked_today: 0 });
  const [flagged, setFlagged] = useState([]);
  const [lookupIp, setLookupIp] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [sRes, fRes] = await Promise.all([
          fetch('http://127.0.0.1:8000/api/stats/ip-monitoring'),
          fetch('http://127.0.0.1:8000/api/network/flagged-ips')
        ]);
        setStats(await sRes.json());
        setFlagged(await fRes.json());
        setLoading(false);
      } catch (e) {
        console.error(e);
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 15000);

    const ws = new WebSocket('ws://127.0.0.1:8000/ws/events');
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'FLAGGED_CONNECTION') {
        setFlagged(prev => [msg.data, ...prev].slice(0, 50));
        setStats(prev => ({ ...prev, flagged_today: prev.flagged_today + 1 }));
      } else if (msg.type === 'IP_BLOCKED') {
        setFlagged(prev => prev.map(f => f.destination_ip === msg.ip ? { ...f, blocked: true } : f));
        setStats(prev => ({ ...prev, blocked_today: prev.blocked_today + 1 }));
      }
    };

    return () => {
      clearInterval(interval);
      ws.close();
    };
  }, []);

  const handleBlock = async (ip) => {
    try {
      await fetch('http://127.0.0.1:8000/api/network/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
    } catch (e) {
      console.error(e);
    }
  };

  const handleLookup = async () => {
    if (!lookupIp) return;
    setChecking(true);
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/check-ip/${lookupIp}`);
      setLookupResult(await res.json());
    } catch (e) {
      console.error(e);
    }
    setChecking(false);
  };

  const getScoreColor = (score) => {
    if (score >= 90) return 'var(--danger)';
    if (score >= 50) return 'var(--warning)';
    return 'var(--success)';
  };

  if (loading) return <div className="glass-panel skeleton" style={{ height: '500px' }} />;

  return (
    <div className="glass-panel" style={{ padding: '20px', height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div className="label-small">NETWORK THREAT MONITOR</div>
      <h2 style={{ marginBottom: '1.5rem' }}>Malicious IP Activity</h2>

      {/* Summary Strip */}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '1.5rem' }}>
        {[
          { label: 'MONITORED TODAY', val: stats.connections_monitored_today, color: 'var(--accent-gold)' },
          { label: 'FLAGGED HITS', val: stats.flagged_today, color: stats.flagged_today > 0 ? 'var(--danger)' : 'var(--success)' },
          { label: 'AUTO-BLOCKED', val: stats.blocked_today, color: 'var(--warning)' },
        ].map(p => (
          <div key={p.label} style={{ flex: 1, padding: '10px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
             <div className="label-small" style={{ fontSize: '8px' }}>{p.label}</div>
             <div style={{ fontSize: '1.2rem', fontWeight: 800, color: p.color }}>{p.val}</div>
          </div>
        ))}
      </div>

      {/* Live Flagged Connections Table */}
      <div style={{ flex: 1, overflowY: 'auto', marginBottom: '1.5rem', maxHeight: '280px', border: '1px solid rgba(255,255,255,0.03)', borderRadius: '4px' }}>
        {flagged.length > 0 ? (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
            <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
                <th style={{ padding: '8px' }}>MACHINE</th>
                <th style={{ padding: '8px' }}>DESTINATION</th>
                <th style={{ padding: '8px', textAlign: 'center' }}>SCORE</th>
                <th style={{ padding: '8px' }}>LAST SEEN</th>
                <th style={{ padding: '8px' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {flagged.map((f, i) => (
                <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', animation: 'fadeIn 0.3s ease-out' }}>
                  <td style={{ padding: '8px' }}>
                    <div style={{ fontWeight: 600 }}>{f.machine_hostname}</div>
                  </td>
                  <td style={{ padding: '8px' }}>
                    <div style={{ color: 'var(--accent-gold)', fontFamily: 'JetBrains Mono' }}>{f.destination_ip}</div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{f.isp || 'Unknown ISP'}</div>
                  </td>
                  <td style={{ padding: '8px', textAlign: 'center' }}>
                    <span style={{ 
                      padding: '2px 6px', borderRadius: '4px', background: getScoreColor(f.abuse_score), 
                      color: 'white', fontWeight: 800, fontSize: '0.7rem'
                    }}>
                      {f.abuse_score}%
                    </span>
                  </td>
                  <td style={{ padding: '8px', color: 'var(--text-muted)' }}>
                    {new Date(f.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td style={{ padding: '8px' }}>
                    <button 
                      disabled={f.blocked}
                      onClick={() => handleBlock(f.destination_ip)}
                      style={{ 
                        background: 'none', 
                        border: f.blocked ? '1px solid var(--text-muted)' : '1px solid var(--danger)', 
                        color: f.blocked ? 'var(--text-muted)' : 'var(--danger)', 
                        padding: '2px 8px', borderRadius: '4px', fontSize: '0.65rem', cursor: f.blocked ? 'default' : 'pointer' 
                      }}
                    >
                      {f.blocked ? 'Blocked' : 'Block'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', padding: '2rem', opacity: 0.5 }}>
             <Shield size={32} color="var(--success)" style={{ marginBottom: '0.5rem' }} />
             <div style={{ color: 'var(--success)', fontWeight: 700 }}>Network is clean</div>
             <div style={{ fontSize: '0.7rem' }}>No malicious connections detected</div>
          </div>
        )}
      </div>

      {/* Mini World Map */}
      <div style={{ height: '180px', background: 'rgba(255,255,255,0.01)', borderRadius: '4px', position: 'relative', overflow: 'hidden', border: '1px solid rgba(255,255,255,0.03)', marginBottom: '1.5rem' }}>
        <svg viewBox="0 0 800 400" style={{ width: '100%', height: '100%' }}>
          {/* Simple world map paths */}
          <path d="M150,100 L250,100 L250,200 L150,200 Z" fill="rgba(184,146,42,0.05)" /> {/* Mock Continents */}
          <path d="M450,150 L550,150 L550,250 L450,250 Z" fill="rgba(184,146,42,0.05)" />
          
          {/* Threat Lines */}
          {flagged.slice(0, 5).map((f, i) => (
            <line 
              key={`line-${i}`} x1="200" y1="150" x2="500" y2="200" 
              stroke="var(--danger)" strokeWidth="0.5" strokeDasharray="2,2" opacity="0.3" 
            />
          ))}

          {/* Your Machine (Gold Dot) */}
          <circle cx="200" cy="150" r="4" fill="var(--accent-gold)" />
          
          {/* Threat Dots */}
          {flagged.map((f, i) => (
            <circle 
              key={`dot-${i}`} cx={300 + (i * 20) % 400} cy={100 + (i * 30) % 250} 
              r="3" fill="var(--danger)" 
              style={{ animation: 'pulseCritical 2s infinite' }}
            />
          ))}
        </svg>
        {flagged.length === 0 && (
          <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', color: 'var(--success)', fontSize: '0.7rem', fontWeight: 600 }}>
             Network is clean
          </div>
        )}
      </div>

      {/* Manual IP Lookup Tool */}
      <div style={{ borderTop: '1px solid var(--border)', paddingTop: '1.5rem' }}>
        <div className="label-small">MANUAL IP LOOKUP</div>
        <div style={{ display: 'flex', gap: '8px', marginTop: '0.5rem' }}>
          <div style={{ flex: 1, position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input 
              type="text" value={lookupIp} onChange={e => setLookupIp(e.target.value)}
              placeholder="Enter any IP address..."
              style={{ width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '4px', padding: '8px 10px 8px 32px', color: 'white', fontSize: '0.8rem' }}
            />
          </div>
          <button 
            onClick={handleLookup} disabled={checking}
            style={{ 
              background: 'none', border: '1px solid var(--accent-gold)', color: 'var(--accent-gold)', 
              borderRadius: '4px', padding: '0 12px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' 
            }}
          >
            {checking ? 'Checking...' : 'Check Reputation'}
          </button>
        </div>

        {lookupResult && (
          <div style={{ marginTop: '1rem', padding: '1rem', background: 'rgba(255,255,255,0.03)', borderRadius: '4px', borderLeft: `3px solid ${getScoreColor(lookupResult.score || 0)}` }}>
             <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>{lookupResult.ip}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{lookupResult.country} | {lookupResult.isp}</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                   <div style={{ fontSize: '0.75rem', color: getScoreColor(lookupResult.score), fontWeight: 800 }}>
                     {lookupResult.score}% Confidence
                   </div>
                   <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Verdict: {lookupResult.score > 75 ? 'Malicious' : lookupResult.score > 25 ? 'Suspicious' : 'Clean'}</div>
                </div>
             </div>
             {lookupResult.score > 50 && (
               <button 
                 onClick={() => handleBlock(lookupResult.ip)}
                 style={{ width: '100%', marginTop: '0.8rem', background: 'var(--danger)', border: 'none', borderRadius: '4px', color: 'white', padding: '6px', fontSize: '0.75rem', fontWeight: 700, cursor: 'pointer' }}
               >
                 Add to Blocklist
               </button>
             )}
          </div>
        )}
      </div>
    </div>
  );
}
