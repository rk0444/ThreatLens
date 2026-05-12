import { useState } from 'react';
import { RefreshCw } from 'lucide-react';

const STATUS_COLOR = {
  Live: 'var(--success)', Active: 'var(--success)', Online: 'var(--success)', Ready: 'var(--success)',
  Delayed: '#f6ad55', // Yellow
  Busy: 'var(--warning)',
  Stale: '#f6ad55',
  Down: 'var(--danger)', Offline: 'var(--danger)',
};

const SERVICES = [
  { key: 'nvd',        label: 'NVD Feed',       retryable: true },
  { key: 'otx',        label: 'OTX Feed',       retryable: true },
  { key: 'abuseipdb',  label: 'AbuseIPDB'      },
  { key: 'virustotal', label: 'VirusTotal'      },
  { key: 'ai',         label: 'AI Pipeline'    },
  { key: 'agent',      label: 'Endpoint Agent' },
];

export default function HealthStrip({ health }) {
  const [retrying, setRetrying] = useState({});

  const handleRetry = async (key) => {
    setRetrying(prev => ({ ...prev, [key]: true }));
    try {
      await fetch(`http://127.0.0.1:8000/api/ingest/${key}`, { method: 'POST' });
      // We don't wait for completion since it's a background thread, just show indicator for a bit
      setTimeout(() => {
        setRetrying(prev => ({ ...prev, [key]: false }));
      }, 3000);
    } catch (e) {
      console.error(e);
      setRetrying(prev => ({ ...prev, [key]: false }));
    }
  };

  return (
    <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', padding: '0.85rem 1.25rem', background: 'rgba(13,27,42,0.7)', border: '1px solid rgba(184,146,42,0.15)', borderRadius: '8px' }}>
      {SERVICES.map(({ key, label, retryable }) => {
        const svc = health?.[key];
        const status = svc?.status || 'Down';
        const color = STATUS_COLOR[status] || 'var(--danger)';
        const isRetrying = retrying[key];

        return (
          <div key={key} title={svc?.detail || ''} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 12px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: '20px', fontSize: '0.72rem', cursor: 'default' }}>
            <div style={{ 
              width: 7, height: 7, borderRadius: '50%', background: color, 
              boxShadow: `0 0 6px ${color}`,
              animation: status === 'Down' ? 'pulseCritical 2s infinite' : 'none'
            }} />
            <span style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>{label}</span>
            <span style={{ color, fontWeight: 700 }}>{status.toUpperCase()}</span>
            
            {retryable && (status === 'Down' || status === 'Delayed') && (
              <button 
                onClick={() => handleRetry(key)}
                disabled={isRetrying}
                style={{ 
                  background: 'none', border: 'none', padding: 0, margin: 0, 
                  color: 'var(--text-muted)', cursor: isRetrying ? 'default' : 'pointer',
                  display: 'flex', alignItems: 'center', transition: 'color 0.2s'
                }}
                onMouseOver={e => e.currentTarget.style.color = 'var(--accent-gold)'}
                onMouseOut={e => e.currentTarget.style.color = 'var(--text-muted)'}
              >
                <RefreshCw size={12} className={isRetrying ? 'spin' : ''} />
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}
