import { useState, useEffect } from 'react';
import { X, ShieldAlert, Globe, ExternalLink } from 'lucide-react';

const getRiskColor = (score) => {
  if (score >= 86) return 'var(--danger)';
  if (score >= 61) return '#fc8181';
  if (score >= 31) return 'var(--warning)';
  return 'var(--success)';
};

export default function CveDrawer({ cve, onClose, footer }) {
  const [actors, setActors] = useState([]);
  const [loadingActors, setLoadingActors] = useState(false);

  useEffect(() => {
    if (cve) {
      setLoadingActors(true);
      fetch(`http://127.0.0.1:8000/api/cves/${cve.cve_id}/threat-actors`)
        .then(r => r.json())
        .then(data => {
          setActors(data);
          setLoadingActors(false);
        })
        .catch(() => setLoadingActors(false));
    }
  }, [cve]);

  if (!cve) return null;

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer" onClick={e => e.stopPropagation()}>
        <div className="drawer-header">
          <div>
            <div className="label-small">{cve.cve_id}</div>
            <h2>CVE Detail</h2>
          </div>
          <button className="close-btn" onClick={onClose}><X /></button>
        </div>
        
        <div className="drawer-content">
          {cve.actively_exploited && (
            <div style={{ background: 'rgba(229, 62, 62, 0.15)', border: '1px solid #fc8181', borderRadius: '4px', padding: '1rem', marginBottom: '2rem', color: '#fc8181', display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <ShieldAlert size={24} />
              <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                ⚠ ACTIVELY EXPLOITED — {cve.ransomware_use ? 'Used in Ransomware Campaigns' : 'Listed in CISA Known Exploited Vulnerabilities Catalog'}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', marginBottom: '2rem' }}>
            <div style={{ position: 'relative' }}>
              <div className="risk-circle-large" style={{ border: `4px solid ${getRiskColor(cve.cvss_score * 10)}` }}>
                {Math.round(cve.cvss_score * 10)}
              </div>
              {cve.actively_exploited && (
                <div style={{ position: 'absolute', top: -5, right: -5, background: 'var(--danger)', borderRadius: '50%', width: 24, height: 24, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '14px', fontWeight: 'bold' }}>!</div>
              )}
            </div>
            <div>
              <div className="label-small">ThreatLens Risk Score</div>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.2rem' }}>
                Composite score based on CVSS, EPSS, and Exploitation status.
              </div>
            </div>
          </div>

          <div className="info-grid">
            <div className="info-item">
              <span className="label-small">CVSS Base Score</span>
              <div className="value">{cve.cvss_score}</div>
            </div>
            <div className="info-item">
              <span className="label-small">EPSS Probability</span>
              <div className="value">{(cve.epss_score * 100).toFixed(2)}%</div>
            </div>
            <div className="info-item">
              <span className="label-small">Published Date</span>
              <div className="value">{new Date(cve.published_date).toLocaleDateString()}</div>
            </div>
            <div className="info-item">
              <span className="label-small">Status</span>
              <div className="value" style={{ color: cve.actively_exploited ? 'var(--danger)' : 'var(--success)' }}>
                {cve.actively_exploited ? 'Critical Risk' : 'Monitoring'}
              </div>
            </div>
          </div>

          <div className="description-box" style={{ marginTop: '2rem' }}>
            <div className="label-small">Description</div>
            <p style={{ lineHeight: 1.6, marginTop: '0.5rem' }}>{cve.description}</p>
          </div>

          <div className="asset-section" style={{ marginTop: '2rem' }}>
            <div className="label-small">Attribution: Threat Actors</div>
            {loadingActors ? (
              <div className="skeleton" style={{ height: '100px', marginTop: '1rem' }}></div>
            ) : actors.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1rem' }}>
                {actors.map((item, idx) => (
                  <div key={idx} style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '4px', padding: '1rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <div style={{ fontWeight: 600, color: 'var(--accent-gold)' }}>{item.group.name}</div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Origin: {item.group.country} | Motivation: {item.group.motivation}</div>
                      </div>
                      <span className={`severity-badge ${item.confidence === 'confirmed' ? 'severity-critical' : 'severity-medium'}`}>
                        {item.confidence.toUpperCase()}
                      </span>
                    </div>
                    {item.technique_name && (
                      <div style={{ marginTop: '0.5rem', fontSize: '0.85rem' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Primary Technique:</span> {item.technique_name} ({item.technique_id})
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ marginTop: '0.5rem', color: 'var(--text-muted)', fontSize: '0.9rem' }}>No direct attribution mapped for this CVE yet.</div>
            )}
          </div>

          <div style={{ marginTop: '2rem' }}>
             <a 
              href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} 
              target="_blank" 
              rel="noreferrer"
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-gold)', textDecoration: 'none', fontSize: '0.9rem' }}
            >
              View on NVD <ExternalLink size={14} />
            </a>
          </div>

          {footer && (
            <div style={{ marginTop: '2rem' }}>
              {footer}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
