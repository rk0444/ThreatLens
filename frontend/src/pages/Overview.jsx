import { useState, useEffect, useRef } from 'react';
import { Activity, Shield, AlertTriangle, TrendingUp, Brain, Clock, ChevronRight, CheckCircle, X } from 'lucide-react';
import { motion } from 'framer-motion';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const Overview = () => {
  const [metrics, setMetrics] = useState({
    totalCves: 0,
    activeIncidents: 0,
    criticalThreats: 0,
    assetsMonitored: 0
  });
  const [severityBreakdown, setSeverityBreakdown] = useState([]);
  const [activityLog, setActivityLog] = useState([]);
  const [topThreats, setTopThreats] = useState([]);
  const [morningBrief, setMorningBrief] = useState(null);
  const [loading, setLoading] = useState(true);
  const [animateNumbers, setAnimateNumbers] = useState(false);
  const wsRef = useRef(null);

  // Animated number component
  const AnimatedNumber = ({ value, duration = 2000 }) => {
    const [displayValue, setDisplayValue] = useState(0);
    
    useEffect(() => {
      if (!animateNumbers) return;
      
      const startTime = Date.now();
      const endTime = startTime + duration;
      
      const updateNumber = () => {
        const now = Date.now();
        const progress = Math.min((now - startTime) / duration, 1);
        const easeOutQuart = 1 - Math.pow(1 - progress, 4);
        setDisplayValue(Math.floor(easeOutQuart * value));
        
        if (now < endTime) {
          requestAnimationFrame(updateNumber);
        }
      };
      
      updateNumber();
    }, [value, duration, animateNumbers]);

    return displayValue;
  };

  useEffect(() => {
    // Fetch initial data
    fetchOverviewData();
    
    // Setup WebSocket for real-time updates
    wsRef.current = new WebSocket('ws://127.0.0.1:8000/ws/events');
    
    wsRef.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        switch (data.type) {
          case 'OVERVIEW_UPDATE':
            setMetrics(data.data.metrics);
            setSeverityBreakdown(data.data.severityBreakdown);
            setActivityLog(data.data.activityLog);
            setTopThreats(data.data.topThreats);
            break;
          case 'NEW_CVE':
            setActivityLog(prev => [{
              id: Date.now(),
              type: 'CVE',
              message: `New CVE ${data.data.cve_id} detected`,
              timestamp: new Date().toISOString(),
              severity: data.data.severity
            }, ...prev]);
            setMetrics(prev => ({
              ...prev,
              totalCves: prev.totalCves + 1,
              criticalThreats: data.data.severity === 'Critical' ? prev.criticalThreats + 1 : prev.criticalThreats
            }));
            break;
          case 'NEW_INCIDENT':
            setActivityLog(prev => [{
              id: Date.now(),
              type: 'Incident',
              message: `Security incident on ${data.data.machine_hostname}`,
              timestamp: new Date().toISOString(),
              severity: data.data.severity
            }, ...prev]);
            setMetrics(prev => ({
              ...prev,
              activeIncidents: prev.activeIncidents + 1
            }));
            break;
          case 'MORNING_BRIEF':
            setMorningBrief(data.data);
            setActivityLog(prev => [{
              id: Date.now(),
              type: 'Brief',
              message: 'AI Morning Brief generated',
              timestamp: new Date().toISOString(),
              severity: 'info'
            }, ...prev]);
            break;
        }
      } catch (error) {
        console.error('WebSocket message error:', error);
      }
    };

    // Start animations after data loads
    const timer = setTimeout(() => setAnimateNumbers(true), 500);
    
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      clearTimeout(timer);
    };
  }, []);

  const fetchOverviewData = () => {
    setLoading(true);
    fetch('http://127.0.0.1:8000/api/overview')
      .then(res => res.json())
      .then(data => {
        setMetrics(data.metrics);
        setSeverityBreakdown(data.severityBreakdown);
        setActivityLog(data.activityLog);
        setTopThreats(data.topThreats);
        setMorningBrief(data.morningBrief);
        setLoading(false);
      })
      .catch(error => {
        console.error('Failed to fetch overview data:', error);
        setLoading(false);
      });
  };

  const getActivityIcon = (type) => {
    switch (type) {
      case 'CVE': return <AlertTriangle size={14} />;
      case 'Incident': return <Shield size={14} />;
      case 'Brief': return <Brain size={14} />;
      default: return <Activity size={14} />;
    }
  };

  const formatTimeAgo = (timestamp) => {
    const diff = Date.now() - new Date(timestamp).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  };

  const getActivityColor = (type, severity) => {
    if (type === 'Brief') return 'var(--accent-gold)';
    if (severity === 'Critical') return '#fc8181';
    if (severity === 'High') return '#f56565';
    if (severity === 'Medium') return 'var(--warning)';
    return 'var(--success)';
  };

  if (loading) {
    return (
      <div className="page-container" style={{ padding: '24px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.5rem', marginBottom: '2rem' }}>
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

  return (
    <div className="page-container" style={{ padding: '24px' }}>
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
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.5rem', marginBottom: '2rem' }}>
        {[
          { 
            label: 'Total CVEs Today', 
            value: metrics.totalCves, 
            icon: <AlertTriangle size={20} />,
            color: 'var(--accent-gold)',
            delay: 0.1
          },
          { 
            label: 'Active Incidents', 
            value: metrics.activeIncidents, 
            icon: <Shield size={20} />,
            color: '#fc8181',
            delay: 0.2
          },
          { 
            label: 'Critical Threats', 
            value: metrics.criticalThreats, 
            icon: <TrendingUp size={20} />,
            color: '#dc2626',
            delay: 0.3
          },
          { 
            label: 'Assets Monitored', 
            value: metrics.assetsMonitored, 
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
            {metric.label === 'Critical Threats' && metric.value > 0 && (
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
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
        {/* Severity Breakdown Chart */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="glass-panel"
          style={{ padding: '1.5rem' }}
        >
          <div className="label-small" style={{ marginBottom: '1rem' }}>Severity Breakdown</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={severityBreakdown}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis 
                dataKey="name" 
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
              <Bar 
                dataKey="value" 
                fill="var(--accent-gold)"
                radius={[4, 4, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Top 5 Critical Threats */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.6 }}
          className="glass-panel"
          style={{ padding: '1.5rem' }}
        >
          <div className="label-small" style={{ marginBottom: '1rem' }}>Top 5 Critical Threats</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {topThreats.map((threat, index) => (
              <div 
                key={threat.id}
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
                onClick={() => {
                  // Navigate to CVE detail
                  window.location.href = `/global-threats#cve-${threat.cve_id}`;
                }}
              >
                <div style={{ flex: 1 }}>
                  <div style={{ 
                    fontFamily: 'JetBrains Mono', 
                    color: 'var(--accent-gold)', 
                    fontSize: '0.85rem',
                    marginBottom: '0.25rem'
                  }}>
                    {threat.cve_id}
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
                </div>
                <div style={{
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  color: threat.risk_score >= 86 ? '#fc8181' : 'var(--text-primary)'
                }}>
                  {threat.risk_score}
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
                No critical threats detected
              </div>
            )}
          </div>
        </motion.div>
      </div>

      {/* Bottom Section */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
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
            AI Morning Brief
            <span style={{
              marginLeft: 'auto',
              fontSize: '0.7rem',
              padding: '0.2rem 0.5rem',
              borderRadius: '10px',
              background: morningBrief ? 'rgba(72, 187, 120, 0.2)' : 'rgba(255,255,255,0.05)',
              color: morningBrief ? 'var(--success)' : 'var(--text-muted)'
            }}>
              {morningBrief ? 'Ready' : 'Generating...'}
            </span>
          </div>
          
          {morningBrief ? (
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
                fontStyle: 'italic'
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
                <span>Generated: {new Date(morningBrief.date).toLocaleDateString()}</span>
                <button
                  onClick={() => {
                    // Navigate to full brief
                    window.location.href = '/morning-brief';
                  }}
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
                  Read More <ChevronRight size={12} />
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
              <div style={{ marginBottom: '1rem' }}>AI Morning Brief</div>
              <div>Generating at 08:00 UTC...</div>
              <div style={{ 
                width: '40px', 
                height: '2px', 
                background: 'var(--border)', 
                margin: '1rem auto',
                borderRadius: '1px'
              }}></div>
              <div style={{ fontSize: '0.8rem' }}>Check back after 08:00 UTC for today's security briefing</div>
            </div>
          )}
        </motion.div>
      </div>

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
