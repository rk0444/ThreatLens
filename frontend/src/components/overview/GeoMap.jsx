// Geographic Threat Map — built with pure SVG (no react-simple-maps, incompatible with React 19)
// Uses a simplified equirectangular projection to plot dots on a world outline

const PROJECT_COORDS = (lat, lng, w, h) => {
  const x = ((lng + 180) / 360) * w;
  const y = ((90 - lat) / 180) * h;
  return [x, y];
};

const DOTS_DEFAULT = [
  { country: 'Russia',        lat: 55.75, lng: 37.61,  count: 0, latest_campaign: '' },
  { country: 'China',         lat: 39.91, lng: 116.39, count: 0, latest_campaign: '' },
  { country: 'North Korea',   lat: 39.02, lng: 125.75, count: 0, latest_campaign: '' },
  { country: 'Iran',          lat: 35.69, lng: 51.42,  count: 0, latest_campaign: '' },
];

export default function GeoMap({ threats }) {
  const W = 700, H = 320;
  const dots = (threats && threats.length > 0) ? threats : DOTS_DEFAULT;
  const maxCount = Math.max(...dots.map(d => d.count), 1);

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', position: 'relative' }}>
      <div className="label-small" style={{ marginBottom: '0.25rem' }}>OSINT INTELLIGENCE</div>
      <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '1rem' }}>Geographic Threat Origins</div>
      <div style={{ position: 'relative', width: '100%', borderRadius: '6px', overflow: 'hidden', background: '#0a1628' }}>
        <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', display: 'block' }}>
          {/* Ocean fill */}
          <rect width={W} height={H} fill="#0a1628" />
          {/* Simplified latitude/longitude grid */}
          {[-60,-30,0,30,60].map(lat => {
            const [,y] = PROJECT_COORDS(lat, 0, W, H);
            return <line key={lat} x1={0} y1={y} x2={W} y2={y} stroke="rgba(184,146,42,0.08)" strokeWidth={0.5} />;
          })}
          {[-120,-60,0,60,120].map(lng => {
            const [x] = PROJECT_COORDS(0, lng, W, H);
            return <line key={lng} x1={x} y1={0} x2={x} y2={H} stroke="rgba(184,146,42,0.08)" strokeWidth={0.5} />;
          })}
          {/* Threat dots */}
          {dots.map((d, i) => {
            const [x, y] = PROJECT_COORDS(d.lat, d.lng, W, H);
            const r = d.count > 0 ? 5 + (d.count / maxCount) * 14 : 4;
            return (
              <g key={i}>
                <circle cx={x} cy={y} r={r * 1.8} fill="rgba(229,62,62,0.08)">
                  {d.count > 0 && <animate attributeName="r" values={`${r*1.8};${r*2.8};${r*1.8}`} dur="2.5s" repeatCount="indefinite"/>}
                </circle>
                <circle cx={x} cy={y} r={r} fill={d.count > 0 ? '#fc8181' : '#4a5568'} fillOpacity={d.count > 0 ? 0.85 : 0.4}>
                  {d.count > 0 && <animate attributeName="fill-opacity" values="0.85;0.5;0.85" dur="2.5s" repeatCount="indefinite"/>}
                </circle>
                <title>{d.country} | {d.count} alerts | {d.latest_campaign || 'No active campaign'}</title>
              </g>
            );
          })}
        </svg>
        {(!threats || threats.length === 0) && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(10,22,40,0.6)', fontSize: '0.85rem', color: 'var(--text-muted)', letterSpacing: '0.5px' }}>
            No active campaign origins detected
          </div>
        )}
      </div>
      <div style={{ display: 'flex', gap: '16px', marginTop: '0.75rem', flexWrap: 'wrap' }}>
        {dots.filter(d => d.count > 0).slice(0, 6).map((d, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#fc8181' }} />
            {d.country}: <strong style={{ color: '#fc8181' }}>{d.count}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}
