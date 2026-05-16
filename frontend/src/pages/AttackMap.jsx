import { useEffect, useRef, useState, useCallback } from 'react';

const THREAT_COLORS = {
  critical: { dot: '#ef4444', ring: '#ef444430', glow: '#ef4444cc' },
  high:     { dot: '#f97316', ring: '#f9731630', glow: '#f97316cc' },
  medium:   { dot: '#eab308', ring: '#eab30830', glow: '#eab308cc' },
  low:      { dot: '#22d3ee', ring: '#22d3ee30', glow: '#22d3eecc' },
};

const MOTIVATION_COLOR = {
  Financial:  '#f97316',
  Espionage:  '#818cf8',
  Disruption: '#ef4444',
  Unknown:    '#64748b',
};

const AttackMap = () => {
  const mapRef       = useRef(null);
  const leafletMap   = useRef(null);
  const markersRef   = useRef([]);
  const [mapData, setMapData]       = useState(null);
  const [selected, setSelected]     = useState(null);
  const [latLon, setLatLon]         = useState({ lat: '0.00', lon: '0.00' });
  const [tickerIdx, setTickerIdx]   = useState(0);
  const [leafletReady, setLeafletReady] = useState(false);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [activeTab, setActiveTab]   = useState('actors');
  const [filter, setFilter]         = useState('all');

  // Load Leaflet from CDN
  useEffect(() => {
    if (window.L) { setLeafletReady(true); return; }
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
    document.head.appendChild(link);
    const script = document.createElement('script');
    script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
    script.onload = () => setLeafletReady(true);
    document.head.appendChild(script);
  }, []);

  // Fetch real data from backend — refreshes every 60s
  const fetchData = useCallback(() => {
    fetch('http://127.0.0.1:8000/api/attack-map')
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(d  => { setMapData(d); setLoading(false); setError(null); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, []);

  useEffect(() => {
    fetchData();
    const t = setInterval(fetchData, 60000);
    return () => clearInterval(t);
  }, [fetchData]);

  // Init Leaflet map
  useEffect(() => {
    if (!leafletReady || !mapRef.current || leafletMap.current) return;
    const L   = window.L;
    const map = L.map(mapRef.current, {
      center: [20, 15], zoom: 2,
      zoomControl: false, attributionControl: false,
      minZoom: 2, maxZoom: 8,
    });
    L.tileLayer(
      'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
      { opacity: 0.9 }
    ).addTo(map);
    map.on('mousemove', e => setLatLon({
      lat: e.latlng.lat.toFixed(2),
      lon: e.latlng.lng.toFixed(2),
    }));
    map.on('click', () => setSelected(null));
    leafletMap.current = map;
  }, [leafletReady]);

  // Place markers whenever data or filter changes
  useEffect(() => {
    if (!leafletMap.current || !mapData?.nodes) return;
    const L   = window.L;
    const map = leafletMap.current;

    markersRef.current.forEach(m => map.removeLayer(m));
    markersRef.current = [];

    const nodes = filter === 'all'
      ? mapData.nodes
      : mapData.nodes.filter(n => n.threat_level === filter);

    nodes.forEach(node => {
      const c       = THREAT_COLORS[node.threat_level] || THREAT_COLORS.low;
      const dotSize = node.threat_level === 'critical' ? 16
                    : node.threat_level === 'high'     ? 13
                    : node.threat_level === 'medium'   ? 10 : 8;
      const ring    = dotSize * 2.6;

      const icon = L.divIcon({
        className: '',
        html: `<div style="position:relative;width:${ring}px;height:${ring}px;pointer-events:auto;">
          <div style="
            position:absolute;top:50%;left:50%;
            transform:translate(-50%,-50%);
            width:${ring}px;height:${ring}px;border-radius:50%;
            background:${c.ring};border:1px solid ${c.dot}44;
            animation:pulse-ring ${node.threat_level === 'critical' ? '1.4' : '2.4'}s ease-out infinite;
          "></div>
          <div style="
            position:absolute;top:50%;left:50%;
            transform:translate(-50%,-50%);
            width:${dotSize}px;height:${dotSize}px;border-radius:50%;
            background:${c.dot};
            box-shadow:0 0 8px ${c.glow},0 0 20px ${c.ring};
          "></div>
        </div>`,
        iconSize:   [ring, ring],
        iconAnchor: [ring / 2, ring / 2],
      });

      const marker = L.marker([node.lat, node.lng], { icon })
        .addTo(map)
        .on('click', e => {
          e.originalEvent.stopPropagation();
          setSelected(node);
          setActiveTab('actors');
        });
      markersRef.current.push(marker);
    });
  }, [mapData, filter, leafletReady]);

  // Ticker rotation
  useEffect(() => {
    if (!mapData?.ticker?.length) return;
    const t = setInterval(() => setTickerIdx(i => (i + 1) % mapData.ticker.length), 6000);
    return () => clearInterval(t);
  }, [mapData]);

  const ticker      = mapData?.ticker?.[tickerIdx] || '';
  const tickerColor = ticker.startsWith('[RED]')    ? '#ef4444'
                    : ticker.startsWith('[ORANGE]') ? '#f97316'
                    : '#94a3b8';
  const summary = mapData?.summary || {};

  return (
    <div style={{
      position: 'relative', width: '100%', height: '100%',
      background: '#060a0f', overflow: 'hidden',
      display: 'flex', flexDirection: 'column',
    }}>

      {/* Top bar */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, zIndex: 1000,
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '10px 18px',
        background: 'linear-gradient(to bottom, rgba(6,10,15,0.97) 60%, transparent)',
        pointerEvents: 'none',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '8px', height: '8px', borderRadius: '50%',
            background: loading ? '#eab308' : error ? '#ef4444' : '#22c55e',
            boxShadow: `0 0 6px ${loading ? '#eab308' : error ? '#ef4444' : '#22c55e'}`,
            animation: 'pulse-dot 2s ease-in-out infinite',
          }} />
          <span style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '0.72rem', letterSpacing: '0.16em', color: '#cbd5e1', fontWeight: 600,
          }}>GLOBAL THREAT OPERATIONS</span>
          {loading && <span style={{ fontSize: '0.65rem', color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>LOADING INTEL…</span>}
          {error   && <span style={{ fontSize: '0.65rem', color: '#ef4444', fontFamily: 'JetBrains Mono, monospace' }}>⚠ BACKEND UNREACHABLE</span>}
        </div>

        {/* Live summary stats from real DB */}
        <div style={{ display: 'flex', gap: '20px', alignItems: 'center', pointerEvents: 'auto' }}>
          {[
            { label: 'COUNTRIES', value: summary.active_countries },
            { label: 'ACTORS',    value: summary.tracked_actors },
            { label: 'CVEs',      value: summary.total_cves },
            { label: 'KEV',       value: summary.kev_count },
            { label: 'OSINT',     value: summary.osint_alerts },
            { label: 'INCIDENTS', value: summary.active_incidents },
          ].map(({ label, value }) => (
            <div key={label} style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '0.58rem', color: '#475569', letterSpacing: '0.1em', fontFamily: 'JetBrains Mono, monospace' }}>{label}</div>
              <div style={{ fontSize: '0.82rem', color: '#f1f5f9', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>
                {value ?? '—'}
              </div>
            </div>
          ))}
          <span style={{ fontSize: '0.65rem', color: '#475569', fontFamily: 'JetBrains Mono, monospace', marginLeft: '8px' }}>
            {latLon.lat}° {latLon.lon}°
          </span>
        </div>
      </div>

      {/* Filter bar */}
      <div style={{
        position: 'absolute', top: '52px', left: '18px', zIndex: 1000,
        display: 'flex', gap: '6px',
      }}>
        {['all', 'critical', 'high', 'medium', 'low'].map(f => {
          const col = f === 'all' ? '#94a3b8' : THREAT_COLORS[f]?.dot;
          return (
            <button key={f} onClick={() => setFilter(f)} style={{
              padding: '3px 10px',
              background: filter === f ? `${col}22` : 'rgba(6,10,15,0.75)',
              border: `1px solid ${filter === f ? col : 'rgba(255,255,255,0.07)'}`,
              borderRadius: '12px',
              color: filter === f ? col : '#475569',
              fontSize: '0.62rem', fontFamily: 'JetBrains Mono, monospace',
              letterSpacing: '0.08em', cursor: 'pointer', textTransform: 'uppercase',
              transition: 'all 0.15s',
            }}>{f}</button>
          );
        })}
      </div>

      {/* Map */}
      <div ref={mapRef} style={{ flex: 1, width: '100%' }} />

      {/* Side panel — real data for selected country */}
      {selected && (
        <div style={{
          position: 'absolute', right: 0, top: 0, bottom: '34px',
          width: '320px', zIndex: 1500,
          background: 'rgba(6,10,15,0.97)',
          borderLeft: '1px solid rgba(255,255,255,0.07)',
          backdropFilter: 'blur(20px)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}>
          {/* Header */}
          <div style={{ padding: '16px 18px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontSize: '0.6rem', color: '#475569', fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.12em', marginBottom: '4px' }}>THREAT ORIGIN</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f1f5f9' }}>{selected.country}</div>
                <div style={{ display: 'flex', gap: '8px', marginTop: '6px', flexWrap: 'wrap' }}>
                  <span style={{
                    fontSize: '0.62rem', padding: '2px 8px', borderRadius: '10px',
                    background: `${THREAT_COLORS[selected.threat_level]?.dot}20`,
                    color: THREAT_COLORS[selected.threat_level]?.dot,
                    border: `1px solid ${THREAT_COLORS[selected.threat_level]?.dot}44`,
                    fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase',
                  }}>{selected.threat_level}</span>
                  <span style={{ fontSize: '0.68rem', color: '#64748b' }}>
                    Activity: <span style={{ color: '#94a3b8' }}>{selected.activity_score}</span>
                  </span>
                </div>
              </div>
              <button onClick={() => setSelected(null)} style={{
                background: 'none', border: 'none', color: '#475569',
                cursor: 'pointer', fontSize: '1.2rem', lineHeight: 1, padding: '2px 6px',
              }}>×</button>
            </div>

            {/* Stats from real DB */}
            <div style={{ display: 'flex', gap: '18px', marginTop: '12px' }}>
              {[
                { label: 'Actors', value: selected.actor_count },
                { label: 'CVEs',   value: selected.cve_count },
                { label: 'OSINT',  value: selected.osint_count },
              ].map(({ label, value }) => (
                <div key={label}>
                  <div style={{ fontSize: '0.58rem', color: '#475569', fontFamily: 'JetBrains Mono, monospace' }}>{label.toUpperCase()}</div>
                  <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f1f5f9', fontFamily: 'JetBrains Mono, monospace' }}>{value}</div>
                </div>
              ))}
            </div>

            {/* Sectors detected from OSINT */}
            {selected.sectors?.length > 0 && (
              <div style={{ marginTop: '10px', display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                {selected.sectors.map(s => (
                  <span key={s} style={{
                    fontSize: '0.6rem', padding: '2px 7px', borderRadius: '8px',
                    background: 'rgba(129,140,248,0.1)',
                    border: '1px solid rgba(129,140,248,0.2)',
                    color: '#818cf8',
                  }}>{s}</span>
                ))}
              </div>
            )}
          </div>

          {/* Tabs */}
          <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            {['actors', 'cves'].map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)} style={{
                flex: 1, padding: '8px', background: activeTab === tab ? 'rgba(255,255,255,0.04)' : 'none',
                border: 'none',
                borderBottom: activeTab === tab ? '2px solid #818cf8' : '2px solid transparent',
                color: activeTab === tab ? '#f1f5f9' : '#475569',
                fontSize: '0.7rem', fontFamily: 'JetBrains Mono, monospace',
                letterSpacing: '0.08em', cursor: 'pointer', textTransform: 'uppercase',
                transition: 'all 0.15s',
              }}>{tab}</button>
            ))}
          </div>

          {/* Content */}
          <div style={{ flex: 1, overflow: 'auto', padding: '12px' }}>
            {activeTab === 'actors' && selected.actors?.map((actor, i) => (
              <div key={i} style={{
                padding: '10px 12px', marginBottom: '8px',
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: '8px',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#e2e8f0' }}>{actor.name}</span>
                  <span style={{ fontSize: '0.6rem', fontFamily: 'JetBrains Mono, monospace', color: '#475569' }}>{actor.mitre_id}</span>
                </div>
                <div style={{ display: 'flex', gap: '6px', marginBottom: '6px', flexWrap: 'wrap' }}>
                  <span style={{
                    fontSize: '0.6rem', padding: '1px 6px', borderRadius: '8px',
                    background: `${MOTIVATION_COLOR[actor.motivation] || '#64748b'}18`,
                    color: MOTIVATION_COLOR[actor.motivation] || '#64748b',
                    border: `1px solid ${MOTIVATION_COLOR[actor.motivation] || '#64748b'}33`,
                  }}>{actor.motivation}</span>
                  <span style={{ fontSize: '0.6rem', color: '#64748b' }}>{actor.cve_count} CVEs</span>
                  {actor.incident_hits > 0 && (
                    <span style={{ fontSize: '0.6rem', color: '#ef4444' }}>⚠ {actor.incident_hits} incident{actor.incident_hits > 1 ? 's' : ''}</span>
                  )}
                  {actor.osint_hits > 0 && (
                    <span style={{ fontSize: '0.6rem', color: '#f97316' }}>● {actor.osint_hits} OSINT</span>
                  )}
                </div>
                {actor.techniques?.length > 0 && (
                  <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                    {actor.techniques.slice(0, 4).map((t, j) => (
                      <span key={j} style={{
                        fontSize: '0.56rem', padding: '1px 5px', borderRadius: '4px',
                        background: 'rgba(255,255,255,0.04)',
                        color: '#64748b', border: '1px solid rgba(255,255,255,0.05)',
                      }}>{t}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}

            {activeTab === 'cves' && (
              <div>
                {selected.top_cves?.length > 0
                  ? selected.top_cves.map((cve, i) => (
                    <div key={i} style={{
                      padding: '8px 12px', marginBottom: '6px',
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid rgba(255,255,255,0.06)',
                      borderRadius: '6px',
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '0.75rem', color: '#94a3b8',
                    }}>{cve}</div>
                  ))
                  : <div style={{ color: '#475569', fontSize: '0.8rem', padding: '12px' }}>No CVEs linked to this country.</div>
                }
              </div>
            )}
          </div>
        </div>
      )}

      {/* Legend */}
      <div style={{
        position: 'absolute', bottom: '42px', left: '18px', zIndex: 1000,
        background: 'rgba(6,10,15,0.82)', padding: '10px 14px',
        borderRadius: '8px', backdropFilter: 'blur(10px)',
        border: '1px solid rgba(255,255,255,0.06)',
        display: 'flex', flexDirection: 'column', gap: '6px',
      }}>
        {Object.entries(THREAT_COLORS).map(([level, c]) => (
          <div key={level} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: c.dot, boxShadow: `0 0 5px ${c.dot}` }} />
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', color: '#94a3b8', textTransform: 'capitalize' }}>{level}</span>
          </div>
        ))}
        <div style={{ marginTop: '4px', paddingTop: '6px', borderTop: '1px solid rgba(255,255,255,0.06)', fontSize: '0.58rem', color: '#334155', fontFamily: 'JetBrains Mono, monospace' }}>
          Source: MITRE ATT&CK + OSINT + CVE DB
        </div>
      </div>

      {/* Zoom buttons */}
      <div style={{
        position: 'absolute', right: selected ? '336px' : '18px', bottom: '50px',
        zIndex: 1000, display: 'flex', flexDirection: 'column', gap: '4px',
        transition: 'right 0.2s',
      }}>
        {['+', '−'].map((lbl, i) => (
          <button key={i}
            onClick={() => leafletMap.current && (i === 0 ? leafletMap.current.zoomIn() : leafletMap.current.zoomOut())}
            style={{
              width: '32px', height: '32px', background: 'rgba(8,12,20,0.85)',
              border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px',
              color: '#94a3b8', fontSize: '1.1rem', cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              backdropFilter: 'blur(8px)', transition: 'color 0.15s',
            }}
            onMouseEnter={e => e.currentTarget.style.color = '#f1f5f9'}
            onMouseLeave={e => e.currentTarget.style.color = '#94a3b8'}
          >{lbl}</button>
        ))}
      </div>

      {/* Live ticker — real OSINT alerts */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0,
        right: selected ? '320px' : 0,
        zIndex: 1000, background: 'rgba(6,10,15,0.95)',
        borderTop: '1px solid rgba(255,255,255,0.06)',
        padding: '6px 18px', display: 'flex', alignItems: 'center', gap: '14px',
        backdropFilter: 'blur(10px)', transition: 'right 0.2s',
      }}>
        <span style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem',
          fontWeight: 700, color: '#22c55e', letterSpacing: '0.12em', flexShrink: 0,
        }}>● LIVE</span>
        <span style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem',
          color: tickerColor, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
        }}>{ticker}</span>
      </div>

      <style>{`
        .leaflet-container { background: #060a0f !important; }
        .leaflet-tile-pane { filter: brightness(0.65) saturate(0.3); }
        @keyframes pulse-ring {
          0%   { transform: translate(-50%,-50%) scale(0.7); opacity: 0.9; }
          100% { transform: translate(-50%,-50%) scale(2.2); opacity: 0; }
        }
        @keyframes pulse-dot { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
      `}</style>
    </div>
  );
};

export default AttackMap;