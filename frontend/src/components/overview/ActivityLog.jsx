import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Zap, FileText, Activity, Globe, Info } from 'lucide-react';

const EVENT_CONFIG = {
  NEW_CVE:                  { icon: Shield,        color: 'var(--accent-gold)', label: 'CVE Ingested' },
  CRITICAL_CVE:             { icon: AlertTriangle,  color: 'var(--danger)',      label: 'Critical CVE' },
  NEW_INCIDENT:             { icon: AlertTriangle,  color: '#f6ad55',            label: 'Incident Detected' },
  INCIDENT_UPDATE:          { icon: Zap,            color: 'var(--danger)',      label: 'Auto-Response Triggered' },
  MORNING_BRIEF_GENERATED:  { icon: FileText,       color: 'var(--accent-gold)', label: 'Morning Brief Generated' },
  ASSET_ADDED:              { icon: Activity,       color: 'var(--success)',     label: 'Agent Check-in' },
  OSINT_ALERT:              { icon: Globe,          color: '#63b3ed',            label: 'OSINT Alert' },
  DEFAULT:                  { icon: Info,           color: 'var(--text-muted)',  label: 'System Event' },
};

const timeAgo = (ts) => {
  const secs = (Date.now() - ts) / 1000;
  if (secs < 60)  return `${Math.floor(secs)}s ago`;
  if (secs < 3600) return `${Math.floor(secs/60)}m ago`;
  return `${Math.floor(secs/3600)}h ago`;
};

export default function ActivityLog({ events }) {
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 15000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
      <div className="label-small" style={{ marginBottom: '0.25rem' }}>SYSTEM EVENTS</div>
      <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '1rem', display: 'flex', justifyContent: 'space-between' }}>
        Recent Activity Log
        <span style={{ fontSize: '0.75rem', fontWeight: 400, color: 'var(--text-muted)' }}>{events.length} events</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '260px', overflowY: 'auto' }}>
        {events.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '1rem' }}>No events yet — system is monitoring...</div>
        ) : events.slice(0, 15).map((ev, i) => {
          const cfg = EVENT_CONFIG[ev.type] || EVENT_CONFIG.DEFAULT;
          const Icon = cfg.icon;
          return (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 10px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.04)', animation: i === 0 ? 'slideInFromTop 0.3s ease' : 'none' }}>
              <Icon size={15} color={cfg.color} style={{ flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <span style={{ fontSize: '0.75rem', color: cfg.color, fontWeight: 600 }}>{cfg.label}</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginLeft: '6px' }}>
                  {ev.description || ev.data?.type || ev.type}
                </span>
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', flexShrink: 0 }}>{timeAgo(ev.ts)}</div>
            </div>
          );
        })}
      </div>
      <style>{`@keyframes slideInFromTop{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}`}</style>
    </div>
  );
}
