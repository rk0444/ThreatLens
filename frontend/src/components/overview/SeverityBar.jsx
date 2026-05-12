const TIER_CFG = {
  Critical: { color: '#fc8181', bg: 'rgba(229,62,62,0.8)' },
  High:     { color: '#f56565', bg: 'rgba(229,62,62,0.6)' },
  Medium:   { color: '#f6ad55', bg: 'rgba(236,153,75,0.7)' },
  Low:      { color: 'var(--success)', bg: 'rgba(72,187,120,0.7)' },
  Info:     { color: '#a0aec0', bg: 'rgba(113,128,150,0.5)' },
};

export default function SeverityBar({ breakdown }) {
  if (!breakdown || breakdown.length === 0) return null;
  const total = breakdown.reduce((s, b) => s + b.count, 0) || 1;
  return (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
      <div className="label-small" style={{ marginBottom: '0.25rem' }}>TODAY'S CVE DISTRIBUTION</div>
      <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '1rem' }}>Severity Breakdown</div>

      {/* Stacked bar */}
      <div style={{ display: 'flex', height: '32px', borderRadius: '6px', overflow: 'hidden', gap: '1px' }}>
        {breakdown.map(({ tier, count }) => {
          const pct = (count / total) * 100;
          if (pct === 0) return null;
          const cfg = TIER_CFG[tier] || TIER_CFG.Info;
          return (
            <div key={tier} title={`${tier}: ${count} CVEs (${pct.toFixed(1)}%)`}
              style={{ flex: pct, background: cfg.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.7rem', fontWeight: 700, color: 'white', minWidth: pct > 5 ? undefined : 0, overflow: 'hidden', transition: 'flex 0.5s ease' }}>
              {pct > 6 ? count : ''}
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: '16px', marginTop: '0.85rem', flexWrap: 'wrap' }}>
        {breakdown.map(({ tier, count, pct }) => {
          const cfg = TIER_CFG[tier] || TIER_CFG.Info;
          return (
            <div key={tier} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.75rem' }}>
              <div style={{ width: 10, height: 10, borderRadius: '2px', background: cfg.bg, flexShrink: 0 }} />
              <span style={{ color: 'var(--text-secondary)' }}>{tier}:</span>
              <strong style={{ color: cfg.color }}>{count}</strong>
              <span style={{ color: 'var(--text-muted)' }}>— {pct}%</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
