import { useState, useEffect } from 'react';
import { X, ShieldAlert, ExternalLink, Brain, AlertTriangle, Server } from 'lucide-react';

import { getRiskColor } from '../utils/riskScore';

const API = 'http://127.0.0.1:8000';

export default function CveDrawer({ cve, onClose, footer }) {
  const [aiSummary, setAiSummary] = useState(null);
  const [aiStatus, setAiStatus] = useState(null); // null | 'loading' | 'generating' | error text
  const [correlationData, setCorrelationData] = useState(null);

  useEffect(() => {
    if (!cve) return;
    setAiSummary(null);
    setCorrelationData(null);
    // Only a stored summary is loaded here; generating one costs a GPT-4o call, so it waits for a click
    setAiStatus('loading');
    fetch(`${API}/api/cves/${cve.cve_id}/ai-summary`)
      .then(r => r.json())
      .then(data => { setAiSummary(data.generated ? data : null); setAiStatus(null); })
      .catch(() => setAiStatus('Could not load the stored summary'));
    fetch(`${API}/api/cves/${cve.cve_id}/correlations`)
      .then(r => r.json())
      .then(setCorrelationData)
      .catch(() => setCorrelationData(null));
  }, [cve]);

  const generateSummary = async () => {
    setAiStatus('generating');
    try {
      const res = await fetch(`${API}/api/cves/${cve.cve_id}/ai-summary`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
      setAiSummary(data);
      setAiStatus(null);
    } catch (e) {
      setAiStatus(e.message);
    }
  };

  if (!cve) return null;
  const band = (cve.risk_band || 'LOW').toUpperCase();

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
          {!cve.cisa_kev && cve.actively_exploited && (
            <div style={{ background: 'rgba(246, 173, 85, 0.12)', border: '1px solid #f6ad55', borderRadius: '4px', padding: '1rem', marginBottom: '2rem', color: '#f6ad55', display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <AlertTriangle size={24} />
              <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                PUBLIC EXPLOIT AVAILABLE — NVD links an exploit; no confirmed exploitation in the wild
              </div>
            </div>
          )}
          {cve.cisa_kev && (
            <div style={{ background: 'rgba(229, 62, 62, 0.15)', border: '1px solid #fc8181', borderRadius: '4px', padding: '1rem', marginBottom: '2rem', color: '#fc8181', display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <ShieldAlert size={24} />
              <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                ⚠ ACTIVELY EXPLOITED — {cve.ransomware_use ? 'Used in Ransomware Campaigns' : 'Listed in CISA Known Exploited Vulnerabilities Catalog'}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', marginBottom: '2rem' }}>
            <div style={{ position: 'relative' }}>
              <div className="risk-circle-large" style={{ border: `4px solid ${getRiskColor(Math.floor(cve.risk_score ?? 0))}` }}>
  {Math.floor(cve.risk_score ?? 0)}
              </div>
              {cve.cisa_kev && (
                <div style={{ position: 'absolute', top: -5, right: -5, background: 'var(--danger)', borderRadius: '50%', width: 24, height: 24, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '14px', fontWeight: 'bold' }}>!</div>
              )}
            </div>
            <div>
              <div className="label-small">ThreatLens Risk Score</div>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.2rem' }}>
                {band} band. Weighted from CVSS, EPSS percentile, CISA KEV, public exploit, your assets, ransomware use and recency; KEV sets a minimum of HIGH (CRITICAL if it affects your assets).
              </div>
            </div>
          </div>

          <div className="info-grid">
            <div className="info-item">
              <span className="label-small">CVSS Base Score</span>
              <div className="value">{cve.cvss_score ?? 'Not scored by NVD yet'}</div>
            </div>
            <div className="info-item">
              <span className="label-small">EPSS Probability</span>
              <div className="value">{cve.epss_score == null ? 'Not scored by EPSS yet' : `${(cve.epss_score * 100).toFixed(2)}%`}</div>
            </div>
            <div className="info-item">
              <span className="label-small">Published Date</span>
              <div className="value">{new Date(cve.published_date).toLocaleDateString()}</div>
            </div>
            <div className="info-item">
              <span className="label-small">Risk Band</span>
              <div className="value" style={{ color: getRiskColor(Math.floor(cve.risk_score ?? 0)) }}>
                {band}
              </div>
            </div>
          </div>

          <div className="description-box" style={{ marginTop: '2rem' }}>
            <div className="label-small">Description</div>
            <p style={{ lineHeight: 1.6, marginTop: '0.5rem' }}>{cve.description}</p>
          </div>

          {/* Your assets whose software NVD lists as affected (CPE match) */}
          {correlationData?.affected_assets?.length > 0 && (
            <div style={{
              background: 'rgba(245, 158, 11, 0.12)',
              border: '1px solid #f59e0b',
              borderRadius: '6px',
              padding: '1rem',
              marginBottom: '2rem',
              color: '#f59e0b'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
                <Server size={20} />
                <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>AFFECTS YOUR ASSETS</div>
              </div>
              <div style={{ fontSize: '0.85rem', lineHeight: 1.5 }}>
                {correlationData.affected_assets.map(a => `${a.name} (${a.software.join(', ')})`).join('; ')}
              </div>
              <div style={{ fontSize: '0.75rem', marginTop: '0.5rem', color: 'var(--text-muted)' }}>
                Software name matches a product NVD lists as vulnerable; installed versions are not compared.
              </div>
              {correlationData.open_incidents?.length > 0 && (
                <div style={{ marginTop: '0.75rem', fontSize: '0.8rem' }}>
                  <strong>Open incidents on these assets:</strong>{' '}
                  {correlationData.open_incidents.map(i => `INC-${i.id} (${i.severity} ${i.type})`).join(', ')}
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Not evidence that this CVE was exploited.</div>
                </div>
              )}
            </div>
          )}

          {/* AI Summary Section */}
          <div style={{ marginTop: '2rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <Brain size={18} color="var(--accent-gold)" />
              <div className="label-small" style={{ margin: 0 }}>AI Analyst Summary (GPT-4o)</div>
            </div>

            {aiStatus === 'loading' ? (
              <div className="skeleton" style={{ height: '20px', width: '60%' }}></div>
            ) : aiSummary ? (
              <div style={{
                background: 'rgba(255,255,255,0.02)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '1.25rem'
              }}>
                <div style={{ display: 'grid', gap: '1rem', marginBottom: '1rem' }}>
                  {[['What is Affected', aiSummary.what_is_affected],
                    ['How It Works', aiSummary.how_it_works],
                    ['What to Do Right Now', aiSummary.what_to_do_now]].map(([title, text]) => (
                    <div key={title}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem', fontSize: '0.9rem' }}>
                        {title}
                      </div>
                      <div style={{ color: 'var(--text-secondary)', lineHeight: 1.5, fontSize: '0.85rem' }}>
                        {text}
                      </div>
                    </div>
                  ))}
                </div>
                <div style={{
                  paddingTop: '0.75rem',
                  borderTop: '1px solid var(--border)',
                  fontSize: '0.75rem',
                  color: 'var(--text-muted)'
                }}>
                  AI-generated by GPT-4o from this CVE's NVD, EPSS and CISA KEV fields at {new Date(aiSummary.generated_at).toLocaleString()}.
                </div>
              </div>
            ) : (
              <div style={{
                background: 'rgba(255,255,255,0.02)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '1.25rem',
                textAlign: 'center',
                color: 'var(--text-muted)',
                fontSize: '0.85rem'
              }}>
                {aiStatus && aiStatus !== 'generating' && (
                  <div style={{ color: 'var(--danger)', marginBottom: '0.75rem' }}>Could not generate summary: {aiStatus}</div>
                )}
                <button className="gold-button" onClick={generateSummary} disabled={aiStatus === 'generating'}>
                  {aiStatus === 'generating' ? 'Generating...' : 'Generate summary with GPT-4o'}
                </button>
              </div>
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
