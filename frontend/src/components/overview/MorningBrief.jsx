import { useState, useEffect } from 'react';
import { FileText, RefreshCw } from 'lucide-react';

const countdownTo8UTC = () => {
  const now = new Date();
  const next = new Date(now);
  next.setUTCHours(8, 0, 0, 0);
  if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
  const diff = Math.floor((next - now) / 1000);
  const h = Math.floor(diff / 3600);
  const m = Math.floor((diff % 3600) / 60);
  const s = diff % 60;
  return `${h}h ${m}m ${s}s`;
};

export default function MorningBrief() {
  const [brief, setBrief]         = useState(null);
  const [loading, setLoading]     = useState(true);
  const [generating, setGenerating] = useState(false);
  const [countdown, setCountdown] = useState(countdownTo8UTC());

  const fetchBrief = () => {
    fetch('http://127.0.0.1:8000/api/morning-brief')
      .then(r => r.ok ? r.json() : null)
      .then(data => { setBrief(data); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchBrief();
    const id = setInterval(() => setCountdown(countdownTo8UTC()), 1000);
    return () => clearInterval(id);
  }, []);

  const regenerate = async () => {
    setGenerating(true);
    await fetch('http://127.0.0.1:8000/api/morning-brief/generate', { method: 'POST' });
    await fetchBrief();
    setGenerating(false);
  };

  const briefDate = brief?.date ? new Date(brief.date) : null;
  const isToday   = briefDate && briefDate.toDateString() === new Date().toDateString();

  return (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
        <div>
          <div className="label-small" style={{ marginBottom: '0.25rem' }}>INTELLIGENCE DIGEST</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <FileText size={20} color="var(--accent-gold)" />
            <span style={{ fontFamily: 'DM Serif Display', fontSize: '1.3rem', color: 'var(--text-primary)' }}>
              AI Morning Brief
            </span>
            {briefDate && (
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {briefDate.toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' })} · Generated {briefDate.toLocaleTimeString('en-GB', { hour:'2-digit', minute:'2-digit' })} UTC
              </span>
            )}
          </div>
        </div>
        <button onClick={regenerate} disabled={generating}
          style={{ display: 'flex', alignItems: 'center', gap: '5px', background: 'rgba(184,146,42,0.12)', border: '1px solid rgba(184,146,42,0.3)', color: 'var(--accent-gold)', borderRadius: '4px', padding: '5px 12px', fontSize: '0.75rem', fontWeight: 600, cursor: generating ? 'not-allowed' : 'pointer', opacity: generating ? 0.7 : 1 }}>
          <RefreshCw size={13} style={{ animation: generating ? 'spin 1s linear infinite' : 'none' }} />
          {generating ? 'Generating...' : 'Regenerate Brief'}
        </button>
      </div>

      {/* Content */}
      {loading ? (
        <div style={{ display: 'flex', gap: '6px', alignItems: 'center', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          <div className="skeleton" style={{ width: '100%', height: '60px', borderRadius: '4px' }} />
        </div>
      ) : generating ? (
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', padding: '1.25rem', background: 'rgba(255,255,255,0.02)', borderLeft: '3px solid var(--accent-gold)', borderRadius: '0 4px 4px 0', fontStyle: 'italic', color: 'var(--text-muted)' }}>
          <span>AI is analysing threats</span>
          {[0,1,2].map(i => (
            <div key={i} style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-gold)', animation: `pulseCritical 1.2s ${i*0.2}s infinite` }} />
          ))}
        </div>
      ) : brief && isToday ? (
        <div style={{ padding: '1.25rem', background: 'rgba(184,146,42,0.04)', borderLeft: '3px solid var(--accent-gold)', borderRadius: '0 6px 6px 0', lineHeight: 1.75, fontFamily: 'DM Serif Display', fontSize: '1rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
          {brief.content}
        </div>
      ) : (
        <div style={{ padding: '1.25rem', background: 'rgba(255,255,255,0.02)', borderLeft: '3px solid rgba(184,146,42,0.3)', borderRadius: '0 6px 6px 0', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontStyle: 'italic' }}>Today's brief will be generated at 08:00 UTC</span>
          <span style={{ fontFamily: 'JetBrains Mono', color: 'var(--accent-gold)', fontSize: '0.85rem' }}>{countdown}</span>
        </div>
      )}
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}
