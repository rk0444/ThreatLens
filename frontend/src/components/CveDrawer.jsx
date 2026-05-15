import { useState, useEffect } from 'react';
import { X, ShieldAlert, Globe, ExternalLink, Brain, AlertTriangle, Copy, CheckCircle } from 'lucide-react';

import { getRiskScore, getRiskColor } from '../utils/riskScore';

const getMitreStageColor = (stage) => {
  const colors = {
    'Initial Access': '#dc2626',
    'Execution': '#ea580c',
    'Persistence': '#d97706',
    'Privilege Escalation': '#ca8a04',
    'Defense Evasion': '#65a30d',
    'Credential Access': '#16a34a',
    'Discovery': '#0891b2',
    'Lateral Movement': '#2563eb',
    'Collection': '#7c3aed',
    'Exfiltration': '#c026d3',
    'Command and Control': '#db2777',
    'Impact': '#991b1b'
  };
  return colors[stage] || '#6b7280';
};

const copyToClipboard = async (text, commandId) => {
  try {
    await navigator.clipboard.writeText(text);
    setCopiedCommand(commandId);
    setTimeout(() => setCopiedCommand(null), 2000);
  } catch (err) {
    console.error('Failed to copy:', err);
  }
};

export default function CveDrawer({ cve, onClose, footer }) {
  const [actors, setActors] = useState([]);
  const [loadingActors, setLoadingActors] = useState(false);
  const [aiSummary, setAiSummary] = useState(null);
  const [loadingAiSummary, setLoadingAiSummary] = useState(false);
  const [correlationData, setCorrelationData] = useState(null);
  const [loadingCorrelation, setLoadingCorrelation] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState(null);

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

      // Fetch AI summary
      setLoadingAiSummary(true);
      fetch(`http://127.0.0.1:8000/api/cves/${cve.cve_id}/ai-summary`)
        .then(r => r.json())
        .then(data => {
          setAiSummary(data);
          setLoadingAiSummary(false);
        })
        .catch(() => setLoadingAiSummary(false));

      // Fetch correlation data
      setLoadingCorrelation(true);
      fetch(`http://127.0.0.1:8000/api/cves/${cve.cve_id}/correlations`)
        .then(r => r.json())
        .then(data => {
          setCorrelationData(data);
          setLoadingCorrelation(false);
        })
        .catch(() => setLoadingCorrelation(false));
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
              <div className="risk-circle-large" style={{ border: `4px solid ${getRiskColor(getRiskScore(cve))}` }}>
  {getRiskScore(cve)}
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

          {/* Correlation Alert */}
          {correlationData && correlationData.correlation_statement && (
            <div style={{ 
              background: 'linear-gradient(135deg, rgba(251, 191, 36, 0.15), rgba(245, 158, 11, 0.15))', 
              border: '1px solid #f59e0b', 
              borderRadius: '6px', 
              padding: '1rem', 
              marginBottom: '2rem',
              color: '#f59e0b'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
                <AlertTriangle size={20} />
                <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>ACTIVE EXPLOITATION DETECTED</div>
              </div>
              <div style={{ fontSize: '0.85rem', lineHeight: 1.5 }}>
                {correlationData.correlation_statement}
              </div>
              {correlationData.related_incidents && correlationData.related_incidents.length > 0 && (
                <div style={{ marginTop: '0.75rem', fontSize: '0.8rem' }}>
                  <strong>Related Incidents:</strong> {correlationData.related_incidents.map(id => `INC-${id}`).join(', ')}
                </div>
              )}
            </div>
          )}

          {/* AI Summary Section */}
          <div style={{ marginTop: '2rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <Brain size={18} color="var(--accent-gold)" />
              <div className="label-small" style={{ margin: 0 }}>AI Analyst Summary</div>
            </div>
            
            {loadingAiSummary ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div className="skeleton" style={{ height: '20px', width: '60%' }}></div>
                <div className="skeleton" style={{ height: '16px', width: '100%' }}></div>
                <div className="skeleton" style={{ height: '16px', width: '90%' }}></div>
                <div className="skeleton" style={{ height: '16px', width: '85%' }}></div>
              </div>
            ) : aiSummary ? (
              <div style={{ 
                background: 'rgba(255,255,255,0.02)', 
                border: '1px solid var(--border)', 
                borderRadius: '6px', 
                padding: '1.25rem' 
              }}>
                <div style={{ display: 'grid', gap: '1rem', marginBottom: '1rem' }}>
                  <div>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem', fontSize: '0.9rem' }}>
                      What is Affected
                    </div>
                    <div style={{ color: 'var(--text-secondary)', lineHeight: 1.5, fontSize: '0.85rem' }}>
                      {aiSummary.what_is_affected}
                    </div>
                  </div>
                  
                  <div>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem', fontSize: '0.9rem' }}>
                      How It Works
                    </div>
                    <div style={{ color: 'var(--text-secondary)', lineHeight: 1.5, fontSize: '0.85rem' }}>
                      {aiSummary.how_it_works}
                    </div>
                  </div>
                  
                  <div>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem', fontSize: '0.9rem' }}>
                      What to Do Right Now
                    </div>
                    <div style={{ color: 'var(--text-secondary)', lineHeight: 1.5, fontSize: '0.85rem' }}>
                      {aiSummary.what_to_do_now}
                    </div>
                  </div>
                </div>
                
                <div style={{ 
                  display: 'flex', 
                  justifyContent: 'space-between', 
                  alignItems: 'center', 
                  paddingTop: '0.75rem', 
                  borderTop: '1px solid var(--border)',
                  fontSize: '0.75rem',
                  color: 'var(--text-muted)'
                }}>
                  <span>Confidence: {Math.round((aiSummary.confidence_score || 0.7) * 100)}%</span>
                  <span>Generated: {new Date(aiSummary.generated_at).toLocaleString()}</span>
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
                AI analysis unavailable. Check back later.
              </div>
            )}
          </div>

          {/* MITRE ATT&CK Tags */}
          {aiSummary && (aiSummary.mitre_stage || aiSummary.mitre_tags) && (
            <div style={{ marginTop: '2rem' }}>
              <div className="label-small" style={{ marginBottom: '1rem' }}>MITRE ATT&CK Classification</div>
              
              {aiSummary.mitre_stage && (
                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Stage</div>
                  <div 
                    style={{ 
                      display: 'inline-block',
                      background: getMitreStageColor(aiSummary.mitre_stage),
                      color: 'white',
                      padding: '0.5rem 1rem',
                      borderRadius: '20px',
                      fontSize: '0.85rem',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: '0.5px'
                    }}
                  >
                    {aiSummary.mitre_stage}
                  </div>
                </div>
              )}
              
              {aiSummary.mitre_tags && aiSummary.mitre_tags.length > 0 && (
                <div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Techniques</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {aiSummary.mitre_tags.map((tag, idx) => (
                      <span 
                        key={idx}
                        style={{ 
                          background: 'rgba(255,255,255,0.1)',
                          border: '1px solid var(--border)',
                          color: 'var(--text-secondary)',
                          padding: '0.25rem 0.75rem',
                          borderRadius: '12px',
                          fontSize: '0.75rem',
                          fontFamily: 'JetBrains Mono'
                        }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

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
