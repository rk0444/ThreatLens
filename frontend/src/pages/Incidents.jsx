import { useState, useEffect, useRef } from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle, Clock, X, ChevronRight, Activity, FileText, Zap } from 'lucide-react';
import CustomDropdown from '../components/CustomDropdown';

const timeAgo = (dateStr) => {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
};

const SEVERITY_CONFIG = {
  Critical: { className: 'severity-critical', icon: ShieldAlert, color: '#fc8181' },
  High:     { className: 'severity-high',     icon: AlertTriangle, color: '#f56565' },
  Medium:   { className: 'severity-medium',   icon: Activity, color: 'var(--warning)' },
  Low:      { className: 'severity-low',      icon: CheckCircle, color: 'var(--success)' },
};

const STATUS_COLORS = {
  Active:        { bg: 'rgba(229,62,62,0.1)',   border: 'var(--danger)',   text: '#fc8181' },
  Investigating: { bg: 'rgba(236,153,75,0.1)',  border: 'var(--warning)',  text: 'var(--warning)' },
  Resolved:      { bg: 'rgba(72,187,120,0.1)',  border: 'var(--success)',  text: 'var(--success)' },
};

const Incidents = () => {
  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected]   = useState(null);
  const [loading, setLoading]     = useState(true);
  const [newIds, setNewIds]        = useState(new Set());
  const [playbook, setPlaybook]   = useState(null);
  const [playbookLoading, setPlaybookLoading] = useState(false);
  const [analystNote, setAnalystNote] = useState('');
  const [filter, setFilter]        = useState({ severity: 'All', status: 'All' });
  const [expandSandbox, setExpandSandbox] = useState(false);
  const listRef = useRef(null);

  const fetchIncidents = () => {
    fetch('http://127.0.0.1:8000/api/incidents')
      .then(r => r.json())
      .then(data => { setIncidents(data); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchIncidents();

    const socket = new WebSocket('ws://127.0.0.1:8000/ws/events');
    socket.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.type === 'NEW_INCIDENT') {
          setIncidents(prev => [data.data, ...prev]);
          setNewIds(prev => new Set([...prev, data.data.id]));
          setTimeout(() => setNewIds(prev => { const n = new Set(prev); n.delete(data.data.id); return n; }), 3000);
        }
        if (data.type === 'INCIDENT_UPDATE') {
          setIncidents(prev => prev.map(inc => inc.id === data.id ? { ...inc, status: data.status } : inc));
          if (selected?.id === data.id) {
            setSelected(prev => prev ? { ...prev, status: data.status } : null);
          }
        }
      } catch {}
    };
    return () => socket.close();
  }, []);

  const selectIncident = (inc) => {
    setSelected(inc);
    setPlaybook(null);
    setExpandSandbox(false);
    setAnalystNote('');
  };

  const handleRespond = async (action) => {
    if (!selected) return;
    const res = await fetch(`http://127.0.0.1:8000/api/incidents/${selected.id}/respond`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, analyst_note: analystNote })
    });
    const data = await res.json();
    setSelected(prev => prev ? { ...prev, status: data.incident_status } : null);
    setIncidents(prev => prev.map(i => i.id === selected.id ? { ...i, status: data.incident_status } : i));
  };

  const loadPlaybook = async () => {
    setPlaybookLoading(true);
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/incidents/${selected.id}/playbook`);
      const data = await res.json();
      setPlaybook(data);
    } finally {
      setPlaybookLoading(false);
    }
  };

  const filteredIncidents = incidents.filter(inc => {
    if (filter.severity !== 'All' && inc.severity !== filter.severity) return false;
    if (filter.status !== 'All' && inc.status !== filter.status) return false;
    return true;
  });

  const activeCount = incidents.filter(i => i.status === 'Active').length;

  const severityOptions = [
    { value: 'All', label: 'All Severities' },
    { value: 'Critical', label: 'Critical' },
    { value: 'High', label: 'High' },
    { value: 'Medium', label: 'Medium' },
    { value: 'Low', label: 'Low' },
  ];

  const statusOptions = [
    { value: 'All', label: 'All Statuses' },
    { value: 'Active', label: 'Active' },
    { value: 'Investigating', label: 'Investigating' },
    { value: 'Resolved', label: 'Resolved' },
  ];

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', padding: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div>
          <div className="label-small">SOC Operations</div>
          <h1>Live <span className="italic-serif">Incidents</span></h1>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ background: 'rgba(229,62,62,0.15)', border: '1px solid var(--danger)', borderRadius: '6px', padding: '0.5rem 1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--danger)', animation: 'pulseCritical 2s infinite' }}></div>
            <span style={{ color: '#fc8181', fontWeight: 700, fontSize: '1.2rem' }}>{activeCount}</span>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>ACTIVE</span>
          </div>
          {/* Filters */}
          <div className="glass-panel" style={{ padding: '0.5rem 1rem', display: 'flex', gap: '1rem', alignItems: 'center', overflow: 'visible', zIndex: 10 }}>
            <CustomDropdown 
              options={severityOptions}
              value={filter.severity}
              onChange={(val) => setFilter({...filter, severity: val})}
            />
            <CustomDropdown 
              options={statusOptions}
              value={filter.status}
              onChange={(val) => setFilter({...filter, status: val})}
            />
          </div>
        </div>
      </div>

      {/* Main split panel */}
      <div style={{ display: 'grid', gridTemplateColumns: selected ? '40% 60%' : '1fr', gap: '1.5rem', alignItems: 'start' }}>

        {/* LEFT: Incidents Feed */}
        <div className="glass-panel" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div className="label-small">INCIDENT FEED</div>
            <div className="label-small">{filteredIncidents.length} events</div>
          </div>
          <div ref={listRef} style={{ maxHeight: '70vh', overflowY: 'auto' }}>
            {loading ? (
              [1,2,3].map(i => <div key={i} className="skeleton" style={{ margin: '1rem', height: '80px', borderRadius: '4px' }}></div>)
            ) : filteredIncidents.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>No incidents match current filters.</div>
            ) : filteredIncidents.map(inc => {
              const cfg = SEVERITY_CONFIG[inc.severity] || SEVERITY_CONFIG.Low;
              const statusCfg = STATUS_COLORS[inc.status] || STATUS_COLORS.Active;
              const isNew = newIds.has(inc.id);
              const isSelected = selected?.id === inc.id;
              return (
                <div
                  key={inc.id}
                  onClick={() => selectIncident(inc)}
                  style={{
                    padding: '1rem 1.5rem',
                    borderBottom: '1px solid var(--border)',
                    cursor: 'pointer',
                    background: isSelected ? 'rgba(184, 146, 42, 0.08)' : isNew ? 'rgba(184, 146, 42, 0.05)' : 'transparent',
                    borderLeft: isSelected ? '3px solid var(--accent-gold)' : isNew ? '3px solid rgba(184,146,42,0.4)' : '3px solid transparent',
                    transition: 'all 0.3s ease',
                    animation: isNew ? 'slideInFromTop 0.4s ease' : 'none',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className={`severity-badge ${cfg.className}`}>{inc.severity}</span>
                      <span style={{ fontSize: '0.75rem', background: statusCfg.bg, color: statusCfg.text, border: `1px solid ${statusCfg.border}`, padding: '0.1rem 0.5rem', borderRadius: '3px' }}>{inc.status}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                      <Clock size={12} /> {timeAgo(inc.created_at)}
                    </div>
                  </div>
                  <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>{inc.type}</div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontFamily: 'JetBrains Mono' }}>
                      {inc.process_name || inc.network_connection || 'Machine ID: ' + inc.machine_id}
                    </div>
                    {inc.auto_response_action && (
                      <div style={{ fontSize: '0.7rem', color: 'var(--warning)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                        <Zap size={11} /> Auto-responded
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* RIGHT: Incident Detail */}
        {selected && (
          <div className="glass-panel" style={{ maxHeight: '80vh', overflowY: 'auto' }}>
            {/* Detail Header */}
            <div style={{ padding: '1.5rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', position: 'sticky', top: 0, background: 'var(--surface)', zIndex: 10 }}>
              <div>
                <div className="label-small">Machine ID: {selected.machine_id}</div>
                <h2 style={{ margin: '0.25rem 0' }}>{selected.type}</h2>
                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                  <span className={`severity-badge ${(SEVERITY_CONFIG[selected.severity] || SEVERITY_CONFIG.Low).className}`}>{selected.severity}</span>
                  <span style={{ fontSize: '0.75rem', background: (STATUS_COLORS[selected.status] || STATUS_COLORS.Active).bg, color: (STATUS_COLORS[selected.status] || STATUS_COLORS.Active).text, border: `1px solid ${(STATUS_COLORS[selected.status] || STATUS_COLORS.Active).border}`, padding: '0.1rem 0.5rem', borderRadius: '3px' }}>{selected.status}</span>
                </div>
              </div>
              <button className="close-btn" onClick={() => setSelected(null)}><X /></button>
            </div>

            <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              {/* Quick info */}
              <div className="info-grid">
                {selected.process_name && <div className="info-item"><span className="label-small">Process</span><div className="value" style={{ fontFamily: 'JetBrains Mono', fontSize: '0.85rem' }}>{selected.process_name}</div></div>}
                {selected.file_path && <div className="info-item"><span className="label-small">File Path</span><div className="value" style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem', wordBreak: 'break-all' }}>{selected.file_path}</div></div>}
                {selected.network_connection && <div className="info-item"><span className="label-small">Network</span><div className="value" style={{ fontFamily: 'JetBrains Mono' }}>{selected.network_connection}</div></div>}
              </div>

              {/* Timeline */}
              <div>
                <div className="label-small" style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Activity size={14} /> INCIDENT TIMELINE
                </div>
                <div style={{ position: 'relative', paddingLeft: '1.5rem' }}>
                  <div style={{ position: 'absolute', left: '7px', top: 0, bottom: 0, width: '2px', background: 'var(--border)' }}></div>
                  {(!selected.timeline || selected.timeline.length === 0) ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No timeline entries yet.</div>
                  ) : [...selected.timeline].map((entry, idx) => (
                    <div key={idx} style={{ position: 'relative', marginBottom: '1.25rem' }}>
                      <div style={{ position: 'absolute', left: '-1.5rem', top: '4px', width: '14px', height: '14px', borderRadius: '50%', background: idx === 0 ? 'var(--accent-gold)' : 'var(--border)', border: '2px solid var(--surface)' }}></div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>
                        {entry.time ? new Date(typeof entry.time === 'number' ? entry.time * 1000 : entry.time).toLocaleTimeString() : ''}
                        {entry.actor && <span style={{ marginLeft: '0.5rem', color: 'var(--accent-gold)' }}> — {entry.actor}</span>}
                      </div>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>{entry.action || entry.event}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* AI Summary */}
              {selected.ai_summary && (
                <div className="description-box">
                  <div className="label-small" style={{ marginBottom: '0.5rem' }}>AI ANALYSIS</div>
                  <p style={{ lineHeight: 1.6 }}>{selected.ai_summary}</p>
                  {selected.mitre_tags?.length > 0 && (
                    <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                      {selected.mitre_tags.map((tag, i) => (
                        <span key={i} style={{ fontFamily: 'JetBrains Mono', background: 'rgba(184,146,42,0.1)', border: '1px solid var(--accent-gold)', color: 'var(--accent-gold)', padding: '0.15rem 0.5rem', borderRadius: '3px', fontSize: '0.75rem' }}>{tag}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Sandbox Report */}
              {selected.sandbox_verdict && (
                <div>
                  <button
                    onClick={() => setExpandSandbox(!expandSandbox)}
                    style={{ width: '100%', background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', borderRadius: '4px', padding: '0.75rem 1rem', color: 'var(--text-primary)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                  >
                    <span className="label-small" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <FileText size={14} /> SANDBOX REPORT — {selected.sandbox_verdict}
                    </span>
                    <ChevronRight size={16} style={{ transform: expandSandbox ? 'rotate(90deg)' : 'none', transition: '0.2s' }} />
                  </button>
                  {expandSandbox && (
                    <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)', borderTop: 'none', borderRadius: '0 0 4px 4px', padding: '1rem', fontFamily: 'JetBrains Mono', fontSize: '0.8rem', color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>
                      {JSON.stringify(selected.virustotal_result || { note: 'Full sandbox data stored in database.' }, null, 2)}
                    </div>
                  )}
                </div>
              )}

              {/* Auto-Response section */}
              <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '4px', padding: '1.25rem' }}>
                <div className="label-small" style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Zap size={14} /> AUTO-RESPONSE
                </div>
                {selected.auto_response_action ? (
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1rem' }}>
                    <span style={{ color: 'var(--warning)' }}>Action taken:</span> {selected.auto_response_action}
                  </div>
                ) : (
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1rem' }}>No automatic response triggered yet.</div>
                )}

                {selected.status !== 'Resolved' && (
                  <>
                    <textarea
                      value={analystNote}
                      onChange={e => setAnalystNote(e.target.value)}
                      placeholder="Add analyst note (optional)..."
                      style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', borderRadius: '4px', padding: '0.6rem', color: 'var(--text-primary)', fontSize: '0.85rem', resize: 'vertical', minHeight: '60px', boxSizing: 'border-box', marginBottom: '0.75rem' }}
                    />
                    <div style={{ display: 'flex', gap: '0.75rem' }}>
                      <button
                        onClick={() => handleRespond('approve')}
                        style={{ flex: 1, background: 'rgba(72,187,120,0.15)', border: '1px solid var(--success)', color: 'var(--success)', borderRadius: '4px', padding: '0.6rem', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
                      >
                        <CheckCircle size={16} /> Approve & Resolve
                      </button>
                      <button
                        onClick={() => handleRespond('reject')}
                        style={{ flex: 1, background: 'rgba(229,62,62,0.1)', border: '1px solid var(--danger)', color: '#fc8181', borderRadius: '4px', padding: '0.6rem', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
                      >
                        <X size={16} /> Reject — Investigate
                      </button>
                    </div>
                  </>
                )}
              </div>

              {/* Remediation Playbook */}
              <div>
                {!playbook ? (
                  <button
                    className="gold-button"
                    style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
                    onClick={loadPlaybook}
                    disabled={playbookLoading}
                  >
                    <FileText size={18} /> {playbookLoading ? 'Generating...' : 'Generate Remediation Playbook'}
                  </button>
                ) : (
                  <div>
                    <div className="label-small" style={{ marginBottom: '1rem' }}>REMEDIATION PLAYBOOK</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      {playbook.playbook.map((step, i) => (
                        <div key={i} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '4px', padding: '0.75rem 1rem' }}>
                          <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: step.priority === 'Immediate' ? 'rgba(229,62,62,0.2)' : step.priority === 'High' ? 'rgba(236,153,75,0.2)' : 'rgba(255,255,255,0.05)', border: `1px solid ${step.priority === 'Immediate' ? 'var(--danger)' : step.priority === 'High' ? 'var(--warning)' : 'var(--border)'}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.85rem', flexShrink: 0, color: step.priority === 'Immediate' ? 'var(--danger)' : step.priority === 'High' ? 'var(--warning)' : 'var(--text-muted)' }}>
                            {step.step}
                          </div>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>{step.action}</div>
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>{step.priority}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                    {playbook.note && <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '0.75rem', fontStyle: 'italic' }}>{playbook.note}</p>}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      <style>{`
        @keyframes slideInFromTop {
          from { opacity: 0; transform: translateY(-20px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
};

export default Incidents;
