import { useState, useEffect } from 'react';
import { ShieldAlert, TriangleAlert, ExternalLink, Sparkles, Loader2, Server } from 'lucide-react';
import { Modal, Badge, Button, ErrorState, Skeleton } from './ui';

const API = 'http://127.0.0.1:8000';

const formatDate = (value) => (value ? new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '–');

// Content is keyed by CVE so its state starts fresh for each CVE
function CveDetail({ cve }) {
  const [aiSummary, setAiSummary] = useState(null);
  const [aiStatus, setAiStatus] = useState('loading'); // null | 'loading' | 'generating' | error text
  const [correlations, setCorrelations] = useState(null);

  useEffect(() => {
    // Only a stored summary is loaded here; generating one costs a GPT-4o call, so it waits for a click
    fetch(`${API}/api/cves/${cve.cve_id}/ai-summary`)
      .then(r => r.json())
      .then(data => { setAiSummary(data.generated ? data : null); setAiStatus(null); })
      .catch(() => setAiStatus('Could not load the stored summary.'));
    fetch(`${API}/api/cves/${cve.cve_id}/correlations`)
      .then(r => r.json())
      .then(setCorrelations)
      .catch(() => setCorrelations(null));
  }, [cve.cve_id]);

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

  const generating = aiStatus === 'generating';
  const affected = correlations?.affected_assets || [];

  return (
    <div className="stack">
      {cve.cisa_kev ? (
        <div className="callout callout-critical">
          <ShieldAlert size={16} aria-hidden="true" />
          <div>
            <div className="callout-title">Known exploited</div>
            <div className="callout-text">
              Listed in the CISA Known Exploited Vulnerabilities catalog{cve.ransomware_use ? ', with known use in ransomware campaigns' : ''}.
            </div>
          </div>
        </div>
      ) : cve.actively_exploited && (
        <div className="callout callout-high">
          <TriangleAlert size={16} aria-hidden="true" />
          <div>
            <div className="callout-title">Public exploit</div>
            <div className="callout-text">NVD links a public exploit. There is no confirmed exploitation in the wild.</div>
          </div>
        </div>
      )}

      <section>
        <dl className="facts">
          <div><dt>Risk score</dt><dd>{Number(cve.risk_score ?? 0).toFixed(1)}{cve.risk_band && <Badge severity={cve.risk_band} />}</dd></div>
          <div><dt>CVSS base</dt><dd>{cve.cvss_score ?? <span className="muted small">Not scored by NVD yet</span>}</dd></div>
          <div>
            <dt>EPSS probability</dt>
            <dd>
              {cve.epss_score == null ? <span className="muted small">Not scored yet</span> : `${(cve.epss_score * 100).toFixed(2)}%`}
              {cve.epss_percentile != null && <span className="muted small">p{Math.round(cve.epss_percentile * 100)}</span>}
            </dd>
          </div>
          <div><dt>Published</dt><dd>{formatDate(cve.published_date)}</dd></div>
        </dl>
        <p className="muted small" style={{ marginTop: 'var(--s3)' }}>
          The risk score weighs CVSS, EPSS percentile, CISA KEV, a public exploit, your assets, ransomware use and recency.
          KEV sets a minimum of High, or Critical if the CVE affects your assets.
        </p>
      </section>

      <section>
        <h3 className="section-title">Description</h3>
        <p>{cve.description}</p>
      </section>

      {affected.length > 0 && (
        <section>
          <h3 className="section-title">Affects your assets</h3>
          <div className="callout callout-high">
            <Server size={16} aria-hidden="true" />
            <div>
              <ul style={{ listStyle: 'none', display: 'grid', gap: 2 }}>
                {affected.map(a => <li key={a.name}><strong>{a.name}</strong> <span className="callout-text">{a.software.join(', ')}</span></li>)}
              </ul>
              <div className="callout-text small" style={{ marginTop: 'var(--s1)' }}>
                Software name matches a product NVD lists as vulnerable; installed versions are not compared.
              </div>
              {correlations.open_incidents?.length > 0 && (
                <div className="small" style={{ marginTop: 'var(--s2)' }}>
                  Open incidents on these assets: {correlations.open_incidents.map(i => `INC-${i.id} (${i.severity} ${i.type})`).join(', ')}.
                  <span className="callout-text"> Not evidence that this CVE was exploited.</span>
                </div>
              )}
            </div>
          </div>
        </section>
      )}

      <section>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--s2)', marginBottom: 'var(--s2)' }}>
          <h3 className="section-title" style={{ margin: 0 }}>AI analyst summary</h3>
          {aiStatus !== 'loading' && (
            <Button size="sm" icon={generating ? Loader2 : Sparkles} className={generating ? 'is-busy' : undefined}
              onClick={generateSummary} disabled={generating}>
              {generating ? 'Generating…' : aiSummary ? 'Regenerate' : 'Generate with GPT-4o'}
            </Button>
          )}
        </div>
        {aiStatus === 'loading' ? <Skeleton lines={3} /> : (
          <>
            {aiStatus && !generating && <ErrorState title="Could not generate the summary">{aiStatus}</ErrorState>}
            {aiSummary ? (
              <div style={{ display: 'grid', gap: 'var(--s3)' }}>
                {[['What is affected', aiSummary.what_is_affected],
                  ['How it works', aiSummary.how_it_works],
                  ['What to do now', aiSummary.what_to_do_now]].map(([title, text]) => (
                  <div key={title}>
                    <div style={{ fontWeight: 600 }}>{title}</div>
                    <div style={{ color: 'var(--text-2)' }}>{text}</div>
                  </div>
                ))}
                <div className="muted small">
                  Generated by GPT-4o from this CVE's NVD, EPSS and CISA KEV fields, {new Date(aiSummary.generated_at).toLocaleString()}.
                </div>
              </div>
            ) : !aiStatus && (
              <p className="muted">No summary yet. Generating one uses one GPT-4o request.</p>
            )}
          </>
        )}
      </section>

      <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noreferrer"
        style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--s1)', width: 'fit-content' }}>
        View on NVD <ExternalLink size={14} aria-hidden="true" />
      </a>
    </div>
  );
}

export default function CveDrawer({ cve, onClose, footer }) {
  return (
    <Modal
      drawer
      open={Boolean(cve)}
      onClose={onClose}
      footer={cve && footer}
      title={cve && (
        <span style={{ display: 'grid', gap: 2 }}>
          <span className="mono" style={{ fontSize: 'var(--fs-h3)' }}>{cve.cve_id}</span>
          <span className="small muted" style={{ fontWeight: 400 }}>CVE detail</span>
        </span>
      )}
    >
      {cve && <CveDetail key={cve.cve_id} cve={cve} />}
    </Modal>
  );
}
