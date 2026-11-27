import { useState, useEffect, useRef, useCallback } from 'react';
import { Activity, Shield, AlertTriangle, TrendingUp, Brain, Clock, ChevronRight } from 'lucide-react';
import { motion } from 'framer-motion';
import { BarChart, Bar, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useWebSocket } from '../hooks/useWebSocket';
import CveDrawer from '../components/CveDrawer';
import { getRiskColor, getBandColor } from '../utils/riskScore';

const API = 'http://127.0.0.1:8000';

// Server events after which the overview numbers may have changed
const REFRESH_EVENTS = ['CVES_UPDATED', 'NEW_INCIDENT', 'INCIDENT_UPDATE', 'MORNING_BRIEF_GENERATED', 'ASSET_ADDED', 'ASSET_DELETED'];

// Counts from the previous value to the new one (from 0 on first show).
// Defined outside Overview so a re-render of the page doesn't restart it.
const AnimatedNumber = ({ value, duration = 1500 }) => {
  const [display, setDisplay] = useState(0);
  const fromRef = useRef(0);
  useEffect(() => {
    const from = fromRef.current;
    const start = performance.now();
    let frame;
    const tick = (now) => {
      const p = Math.min((now - start) / duration, 1);
      const v = Math.round(from + (value - from) * (1 - Math.pow(1 - p, 4)));
      fromRef.current = v;
      setDisplay(v);
      if (p < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [value, duration]);
  return display;
};

const Overview = () => {
  const [overview, setOverview] = useState(null);
  const [error, setError] = useState(null);
  const [briefStatus, setBriefStatus] = useState(null); // null | 'generating' | error text
  const [loading, setLoading] = useState(true);
  const [selectedCve, setSelectedCve] = useState(null);
  const [threatError, setThreatError] = useState(null);
  const [now, setNow] = useState(() => Date.now());

  // Keep "x m ago" labels current while the page stays open
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60000);
    return () => clearInterval(t);
  }, []);

  const fetchOverviewData = useCallback(() => {
    fetch(`${API}/api/overview`)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => { setOverview(data); setError(null); })
      .catch(e => setError(`Could not load the overview (${e.message}). Is the backend running?`))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchOverviewData(); }, [fetchOverviewData]);

  // Nothing loaded yet (e.g. backend still starting): keep trying until it answers
  useEffect(() => {
    if (overview || !error) return;
    const t = setInterval(fetchOverviewData, 5000);
    return () => clearInterval(t);
  }, [overview, error, fetchOverviewData]);

  useWebSocket(useCallback(msg => {
    if (REFRESH_EVENTS.includes(msg.type)) fetchOverviewData();
  }, [fetchOverviewData]));

  const generateBrief = async () => {
    setBriefStatus('generating');
    try {
      const res = await fetch(`${API}/api/morning-brief/generate`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
      setBriefStatus(null);
      fetchOverviewData();
    } catch (e) {
      setBriefStatus(e.message);
    }
  };

  const openThreat = (cveId) => {
    setThreatError(null);
    fetch(`${API}/api/cves/${encodeURIComponent(cveId)}`)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(setSelectedCve)
      .catch(e => setThreatError(`Could not load ${cveId} (${e.message}).`));
  };

  const { metrics, severityBreakdown = [], activityLog = [], topThreats = [], morningBrief } = overview || {};
  const briefIsToday = morningBrief?.date && new Date(morningBrief.date).toDateString() === new Date().toDateString();

  const getActivityIcon = (type) => {
    switch (type) {
      case 'CVE': return <AlertTriangle size={14} />;
      case 'Incident': return <Shield size={14} />;
      case 'Brief': return <Brain size={14} />;
      default: return <Activity size={14} />;
    }
  };

  const formatTimeAgo = (timestamp) => {
    const diff = now - new Date(timestamp).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  };

  const getActivityColor = (type, severity) => type === 'Brief' ? 'var(--accent-gold)' : getBandColor(severity);

  if (loading) {
    return (
      <div className="page-container" style={{ padding: '24px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
          {[1,2,3,4].map(i => (
            <div key={i} className="glass-panel" style={{ padding: '1.5rem' }}>
              <div className="skeleton" style={{ height: '20px', width: '60%', marginBottom: '1rem' }}></div>
              <div className="skeleton" style={{ height: '40px', width: '40%' }}></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const errorBanner = error && (
    <div role="alert" style={{ marginBottom: '1.5rem', padding: '12px 16px', borderRadius: '6px', border: '1px solid rgba(229,62,62,0.4)', background: 'rgba(74,26,26,0.6)', color: '#fc8181' }}>
      {error}
    </div>
  );

  // Never show zeros as if they were real numbers when nothing has loaded
  if (!overview) {
    return (
      <div className="page-container" style={{ padding: '24px' }}>
        {errorBanner}
        <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Retrying every 5 seconds…</div>
      </div>
    );
  }

  return (
    <div className="page-container" style={{ padding: '24px' }}>
      {errorBanner}
      {/* Hero Section */}
      <div style={{ textAlign: 'center', marginBottom: '3rem', position: 'relative', overflow: 'hidden', padding: '2rem 0' }}>
        {/* Animated Background */}
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
          zIndex: -1, opacity: 0.1, pointerEvents: 'none',
          display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
          <svg width="100%" height="100%" viewBox="0 0 1200 400" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M0,200 Q150,100 300,200 T600,200 T900,200 T1200,200" fill="none" stroke="var(--accent-gold)" strokeWidth="3">
              <animate attributeName="d" dur="12s" repeatCount="indefinite"
                values="M0,200 Q150,100 300,200 T600,200 T900,200 T1200,200;
                        M0,200 Q150,300 300,200 T600,200 T900,200 T1200,200;
                        M0,200 Q150,100 300,200 T600,200 T900,200 T1200,200" />
            </path>
            <path d="M0,250 Q150,350 300,250 T600,250 T900,250 T1200,250" fill="none" stroke="var(--info)" strokeWidth="2">
              <animate attributeName="d" dur="18s" repeatCount="indefinite"
                values="M0,250 Q150,350 300,250 T600,250 T900,250 T1200,250;
                        M0,250 Q150,150 300,250 T600,250 T900,250 T1200,250;
                        M0,250 Q150,350 300,250 T600,250 T900,250 T1200,250" />
            </path>
          </svg>
        </div>

        <motion.h1 
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          style={{ 
            fontSize: '3.5rem', 
            fontWeight: 700, 
            marginBottom: '0.5rem',
            background: 'linear-gradient(135deg, var(--text-primary), var(--accent-gold))',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}
        >
          ThreatLens
        </motion.h1>
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="italic-serif"
          style={{ 
            fontSize: '1.5rem', 
            color: 'var(--accent-gold)',
            marginBottom: '1rem'
          }}
        >
          V2.0
        </motion.div>
        <motion.p 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          style={{ 
            fontSize: '1.1rem', 
            color: 'var(--text-secondary)',
            maxWidth: '600px',
            margin: '0 auto'
          }}
        >
          One dashboard. One priority queue. One AI.
        </motion.p>
      </div>

      {/* Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
        {[
          { 
            label: 'CVEs Published Today', 
            value: metrics.totalCves, 
            icon: <AlertTriangle size={20} />,
            color: 'var(--accent-gold)',
            delay: 0.1
          },
          { 
            label: 'Open Incidents', 
            value: metrics.openIncidents, 
            icon: <Shield size={20} />,
            color: '#fc8181',
            delay: 0.2
          },
          { 
            label: 'Critical CVEs (All Time)', 
            value: metrics.criticalThreats, 
            icon: <TrendingUp size={20} />,
            color: '#dc2626',
            delay: 0.3
          },
          { 
            label: `Agents Reporting (of ${metrics.assetsRegistered})`, 
            value: metrics.agentsOnline, 
            icon: <Activity size={20} />,
            color: 'var(--success)',
            delay: 0.4
          }
        ].map((metric, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: metric.delay }}
            className="glass-panel"
            style={{ 
              padding: '1.5rem',
              borderLeft: `4px solid ${metric.color}`,
              position: 'relative',
              overflow: 'hidden'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
              <div style={{ color: metric.color }}>{metric.icon}</div>
              <div className="label-small" style={{ margin: 0, color: 'var(--text-muted)' }}>
                {metric.label}
              </div>
            </div>
            <div style={{ fontSize: '2.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              <AnimatedNumber value={metric.value} />
            </div>
            {/* Subtle pulse animation for critical metrics */}
            {metric.label === 'Critical CVEs (All Time)' && metric.value > 0 && (
              <div style={{
                position: 'absolute',
                top: 0,
                right: 0,
                width: '8px',
                height: '8px',
                background: metric.color,
                borderRadius: '50%',
                animation: 'pulseCritical 2s infinite'
              }}></div>
            )}
          </motion.div>
        ))}
      </div>

      {/* Main Content Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '1.5rem', marginBottom: '2rem' }}>
        {/* Severity Breakdown Chart */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="glass-panel"
          style={{ padding: '1.5rem' }}
        >
          <div className="label-small" style={{ marginBottom: '1rem' }}>Risk Bands of CVEs Published Today</div>
          {severityBreakdown.some(s => s.value > 0) ? (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={severityBreakdown}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis
                dataKey="name"
                interval={0}
                stroke="var(--text-muted)"
                tick={{ fill: 'var(--text-muted)', fontSize: '0.75rem' }}
              />
              <YAxis 
                stroke="var(--text-muted)"
                tick={{ fill: 'var(--text-muted)', fontSize: '0.75rem' }}
              />
              <Tooltip 
                contentStyle={{ 
                  background: 'var(--surface)', 
                  border: '1px solid var(--border)',
                  borderRadius: '4px'
                }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {severityBreakdown.map(s => <Cell key={s.name} fill={getBandColor(s.name)} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          ) : (
            <div style={{ height: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
              No CVEs published yet today
            </div>
          )}
        </motion.div>

        {/* Top 5 Critical Threats */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.6 }}
          className="glass-panel"
          style={{ padding: '1.5rem' }}
        >
          <div className="label-small" style={{ marginBottom: '1rem' }}>Top 5 by Risk Score (All Time)</div>
          {threatError && (
            <div role="alert" style={{ color: 'var(--danger)', fontSize: '0.8rem', marginBottom: '0.75rem' }}>{threatError}</div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {topThreats.map((threat, index) => (
              <div
                key={threat.id}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openThreat(threat.cve_id); }
                }}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.75rem',
                  background: index === 0 ? 'rgba(229, 62, 62, 0.1)' : 'rgba(255,255,255,0.02)',
                  border: index === 0 ? '1px solid #fc8181' : '1px solid var(--border)',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = 'rgba(184, 146, 42, 0.1)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = index === 0 ? 'rgba(229, 62, 62, 0.1)' : 'rgba(255,255,255,0.02)';
                }}
                onClick={() => openThreat(threat.cve_id)}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ 
                    fontFamily: 'JetBrains Mono', 
                    color: 'var(--accent-gold)', 
                    fontSize: '0.85rem',
                    marginBottom: '0.25rem',
                    display: 'flex', alignItems: 'center', gap: '6px'
                  }}>
                    {threat.cve_id}
                    {threat.cisa_kev && (
                      <span style={{ fontSize: '0.6rem', background: 'rgba(229,62,62,0.2)', border: '1px solid #fc8181', color: '#fc8181', padding: '1px 5px', borderRadius: '3px', fontFamily: 'sans-serif', flexShrink: 0 }}>KEV</span>
                    )}
                  </div>
                  <div style={{ 
                    color: 'var(--text-secondary)', 
                    fontSize: '0.8rem',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                  }}>
                    {threat.description}
                  </div>
                  <div style={{ display: 'flex', gap: '12px', marginTop: '4px', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {threat.cvss_score != null && <span>CVSS {Number(threat.cvss_score).toFixed(1)}</span>}
                    {threat.epss_score != null && <span>EPSS {(Number(threat.epss_score) * 100).toFixed(1)}%</span>}
                  </div>
                </div>
                <div style={{
                  fontSize: '0.9rem',
                  fontWeight: 700,
                  color: getRiskColor(threat.risk_score),
                  marginLeft: '12px',
                  minWidth: '40px',
                  textAlign: 'right',
                  flexShrink: 0
                }}>
                  {threat.risk_score}
                  {threat.risk_band && (
                    <div style={{ fontSize: '0.6rem', letterSpacing: '0.5px', marginTop: '2px' }}>{threat.risk_band}</div>
                  )}
                </div>
              </div>
            ))}
            {topThreats.length === 0 && (
              <div style={{ 
                textAlign: 'center', 
                color: 'var(--text-muted)', 
                fontSize: '0.9rem',
                padding: '2rem 0'
              }}>
                No scored CVEs yet
              </div>
            )}
          </div>
        </motion.div>
      </div>

      {/* Bottom Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '1.5rem' }}>
        {/* Activity Log */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.7 }}
          className="glass-panel"
          style={{ padding: '1.5rem' }}
        >
          <div className="label-small" style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock size={14} />
            Activity Log
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '300px', overflowY: 'auto' }}>
            {activityLog.slice(0, 10).map((activity) => (
              <div 
                key={activity.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  padding: '0.5rem',
                  borderRadius: '4px',
                  fontSize: '0.85rem'
                }}
              >
                <div style={{ color: getActivityColor(activity.type, activity.severity) }}>
                  {getActivityIcon(activity.type)}
                </div>
                <div style={{ flex: 1, color: 'var(--text-secondary)' }}>
                  {activity.message}
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                  {formatTimeAgo(activity.timestamp)}
                </div>
              </div>
            ))}
            {activityLog.length === 0 && (
              <div style={{ 
                textAlign: 'center', 
                color: 'var(--text-muted)', 
                fontSize: '0.9rem',
                padding: '2rem 0'
              }}>
                No recent activity
              </div>
            )}
          </div>
        </motion.div>

        {/* Morning Brief */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.8 }}
          className="glass-panel"
          style={{ padding: '1.5rem' }}
        >
          <div className="label-small" style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Brain size={14} color="var(--accent-gold)" />
            Morning Brief (GPT-4o)
            <span style={{
              marginLeft: 'auto',
              fontSize: '0.7rem',
              padding: '0.2rem 0.5rem',
              borderRadius: '10px',
              background: briefIsToday ? 'rgba(72, 187, 120, 0.2)' : 'rgba(255,255,255,0.05)',
              color: briefIsToday ? 'var(--success)' : 'var(--text-muted)'
            }}>
              {briefStatus === 'generating' ? 'Generating...' : !morningBrief?.content ? 'None yet' : briefIsToday ? "Today's" : 'Out of date'}
            </span>
          </div>
          
          {briefStatus && briefStatus !== 'generating' && (
            <div style={{ color: 'var(--danger)', fontSize: '0.8rem', marginBottom: '0.75rem' }}>
              Could not generate brief: {briefStatus}
            </div>
          )}
          {morningBrief?.content ? (
            <div style={{
              background: 'linear-gradient(135deg, rgba(184, 146, 42, 0.1), rgba(245, 158, 11, 0.05))',
              border: '1px solid var(--accent-gold)',
              borderRadius: '6px',
              padding: '1rem',
              position: 'relative'
            }}>
              <blockquote style={{
                margin: 0,
                padding: 0,
                fontSize: '0.9rem',
                lineHeight: 1.6,
                color: 'var(--text-secondary)',
                fontStyle: 'italic',
                whiteSpace: 'pre-wrap'
              }}>
                {morningBrief.content.split('\n').slice(0, 3).join('\n')}
                {morningBrief.content.split('\n').length > 3 && '...'}
              </blockquote>
              
              <div style={{
                marginTop: '0.75rem',
                paddingTop: '0.75rem',
                borderTop: '1px solid rgba(184, 146, 42, 0.3)',
                fontSize: '0.75rem',
                color: 'var(--text-muted)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <span>Generated: {new Date(morningBrief.date).toLocaleString()}</span>
                <button
                  onClick={generateBrief}
                  disabled={briefStatus === 'generating'}
                  style={{
                    background: 'rgba(255,255,255,0.1)',
                    border: '1px solid var(--border)',
                    borderRadius: '4px',
                    padding: '0.25rem 0.75rem',
                    color: 'var(--accent-gold)',
                    cursor: 'pointer',
                    fontSize: '0.75rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.25rem'
                  }}
                >
                  {briefStatus === 'generating' ? 'Generating...' : 'Regenerate'} <ChevronRight size={12} />
                </button>
              </div>
            </div>
          ) : (
            <div style={{
              textAlign: 'center',
              color: 'var(--text-muted)',
              fontSize: '0.9rem',
              padding: '2rem 0'
            }}>
              <div style={{ marginBottom: '1rem' }}>No brief yet</div>
              <button className="gold-button" onClick={generateBrief} disabled={briefStatus === 'generating'}>
                {briefStatus === 'generating' ? 'Generating...' : 'Generate with GPT-4o'}
              </button>
            </div>
          )}
        </motion.div>
      </div>

      <CveDrawer cve={selectedCve} onClose={() => setSelectedCve(null)} />

      <style>{`
        @keyframes pulseCritical {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  );
};

export default Overview;
