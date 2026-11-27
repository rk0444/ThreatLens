import { useState, useEffect, useCallback } from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle, Clock, X, ChevronRight, Activity, FileText, Copy } from 'lucide-react';
import CustomDropdown from '../components/CustomDropdown';
import { useWebSocket } from '../hooks/useWebSocket';

const API = 'http://127.0.0.1:8000';

const getJson = async (url, options) => {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `HTTP ${res.status}`);
  return data;
};

const timeAgo = (dateStr, now) => {
  const diff = now - new Date(dateStr).getTime();
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
  const [machineNames, setMachineNames] = useState({});
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [actionError, setActionError] = useState(null);
  const [newIds, setNewIds]        = useState(new Set());
  // A playbook belongs to the incident it was generated for; switching incidents mid-request can't mislabel it
  const [playbookResult, setPlaybookResult] = useState(null); // { incidentId, data }
  const [playbookLoadingId, setPlaybookLoadingId] = useState(null);
  const [analystNote, setAnalystNote] = useState('');
  const [filter, setFilter]        = useState({ severity: 'All', status: 'All' });
  const [expandSandbox, setExpandSandbox] = useState(false);
  const [copiedStep, setCopiedStep] = useState(null);
  const [now, setNow] = useState(() => Date.now());

  // Keep "x m ago" labels current while the page stays open
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60000);
    return () => clearInterval(t);
  }, []);

  // The open incident always comes from the latest list, so live updates reach it too
  const selected = incidents.find(i => i.id === selectedId) || null;
  const playbook = playbookResult?.incidentId === selectedId ? playbookResult.data : null;
  const playbookLoading = playbookLoadingId !== null && playbookLoadingId === selectedId;
  const machineLabel = (id) => machineNames[id] || `Machine #${id}`;

  const fetchIncidents = useCallback(() =>
    Promise.all([getJson(`${API}/api/incidents`), getJson(`${API}/api/assets`).catch(() => [])])
      .then(([list, assets]) => {
        setIncidents(list);
        setMachineNames(Object.fromEntries(assets.map(a => [a.id, a.name])));
        setError(null);
      })
      .catch(e => setError(`Could not load incidents (${e.message}). Is the backend running?`))
      .finally(() => setLoading(false)), []);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);

  useWebSocket(useCallback(msg => {
    if (msg.type === 'NEW_INCIDENT') {
      const id = msg.data?.id;
      setNewIds(prev => new Set([...prev, id]));
      setTimeout(() => setNewIds(prev => { const n = new Set(prev); n.delete(id); return n; }), 3000);
    }
    if (['NEW_INCIDENT', 'INCIDENT_UPDATE', 'ASSET_DELETED'].includes(msg.type)) fetchIncidents();
  }, [fetchIncidents]));

  const selectIncident = (inc) => {
    setSelectedId(inc.id);
    setExpandSandbox(false);
    setAnalystNote('');
    setActionError(null);
  };

  const handleRespond = async (action) => {
    if (!selected) return;
    setActionError(null);
    try {
      await getJson(`${API}/api/incidents/${selected.id}/respond`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, analyst_note: analystNote })
      });
      setAnalystNote('');
      fetchIncidents();
    } catch (e) {
      setActionError(`Could not update the incident (${e.message}).`);
    }
  };

  const copyCommand = async (text, step) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedStep(step);
      setTimeout(() => setCopiedStep(s => (s === step ? null : s)), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const loadPlaybook = async () => {
    const incidentId = selected.id;
    setPlaybookLoadingId(incidentId);
    try {
      setPlaybookResult({ incidentId, data: await getJson(`${API}/api/incidents/${incidentId}/playbook`) });
    } catch (e) {
      setPlaybookResult({ incidentId, data: { error: e.message } });
    } finally {
      setPlaybookLoadingId(id => (id === incidentId ? null : id));
    }
  };

  const filteredIncidents = incidents.filter(inc => {
    if (filter.severity !== 'All' && inc.severity !== filter.severity) return false;
    if (filter.status !== 'All' && inc.status !== filter.status) return false;
    return true;
  });

  const openCount = incidents.filter(i => i.status !== 'Resolved').length;

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
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div className="label-small">SOC Operations</div>
          <h1>Live <span className="italic-serif">Incidents</span></h1>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ background: 'rgba(229,62,62,0.15)', border: '1px solid var(--danger)', borderRadius: '6px', padding: '0.5rem 1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--danger)', animation: openCount > 0 ? 'pulseCritical 2s infinite' : 'none' }}></div>
            <span style={{ color: '#fc8181', fontWeight: 700, fontSize: '1.2rem' }}>{openCount}</span>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>OPEN</span>
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
      <div style={{ display: 'grid', gridTemplateColumns: selected ? 'minmax(0, 2fr) minmax(0, 3fr)' : 'minmax(0, 1fr)', gap: '1.5rem', alignItems: 'start' }}>

        {/* LEFT: Incidents Feed */}
        <div className="glass-panel" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div className="label-small">INCIDENT FEED</div>
            <div className="label-small">{filteredIncidents.length} events</div>
          </div>
          <div style={{ maxHeight: '70vh', overflowY: 'auto' }}>
            {loading ? (
              [1,2,3].map(i => <div key={i} className="skeleton" style={{ margin: '1rem', height: '80px', borderRadius: '4px' }}></div>)
            ) : error ? (
              <div role="alert" style={{ padding: '2rem', textAlign: 'center', color: '#fc8181' }}>{error}</div>
            ) : incidents.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                No incidents yet. The network and process monitors file one when they detect something.
              </div>
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
                  role="button"
                  tabIndex={0}
                  onClick={() => selectIncident(inc)}
                  onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectIncident(inc); } }}
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
                      <Clock size={12} /> {timeAgo(inc.created_at, now)}
                    </div>
                  </div>
                  <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>{inc.type}</div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontFamily: 'JetBrains Mono' }}>
                      {inc.process_name || inc.network_connection || ''}
                    </div>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', flexShrink: 0 }}>{machineLabel(inc.machine_id)}</div>
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
                <div className="label-small">{machineLabel(selected.machine_id)}</div>
                <h2 style={{ margin: '0.25rem 0' }}>{selected.type}</h2>
                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                  <span className={`severity-badge ${(SEVERITY_CONFIG[selected.severity] || SEVERITY_CONFIG.Low).className}`}>{selected.severity}</span>
                  <span style={{ fontSize: '0.75rem', background: (STATUS_COLORS[selected.status] || STATUS_COLORS.Active).bg, color: (STATUS_COLORS[selected.status] || STATUS_COLORS.Active).text, border: `1px solid ${(STATUS_COLORS[selected.status] || STATUS_COLORS.Active).border}`, padding: '0.1rem 0.5rem', borderRadius: '3px' }}>{selected.status}</span>
                </div>
              </div>
              <button className="close-btn" aria-label="Close" onClick={() => setSelectedId(null)}><X /></button>
            </div>

            <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              {/* What the monitor recorded */}
              {selected.details && (
                <div>
                  <div className="label-small" style={{ marginBottom: '0.5rem' }}>DETECTION DETAILS</div>
                  <div style={{ color: 'var(--text-secondary)', lineHeight: 1.6, fontSize: '0.9rem' }}>{selected.details}</div>
                </div>
              )}

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
                        {entry.time ? new Date(typeof entry.time === 'number' ? entry.time * 1000 : entry.time).toLocaleString() : ''}
                        {entry.actor && <span style={{ marginLeft: '0.5rem', color: 'var(--accent-gold)' }}> — {entry.actor}</span>}
                      </div>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>{entry.action || entry.event}</div>
                    </div>
                  ))}
                </div>
              </div>

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

              {/* Analyst action: status is set by hand (ThreatLens takes no automatic response actions) */}
              {selected.status !== 'Resolved' && (
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '4px', padding: '1.25rem' }}>
                  <div className="label-small" style={{ marginBottom: '1rem' }}>ANALYST ACTION</div>
                  <textarea
                    value={analystNote}
                    onChange={e => setAnalystNote(e.target.value)}
                    placeholder="Add analyst note (optional, saved in the timeline)..."
                    aria-label="Analyst note"
                    style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', borderRadius: '4px', padding: '0.6rem', color: 'var(--text-primary)', fontSize: '0.85rem', resize: 'vertical', minHeight: '60px', boxSizing: 'border-box', marginBottom: '0.75rem' }}
                  />
                  {actionError && <div role="alert" style={{ color: 'var(--danger)', fontSize: '0.85rem', marginBottom: '0.75rem' }}>{actionError}</div>}
                  <div style={{ display: 'flex', gap: '0.75rem' }}>
                    <button
                      onClick={() => handleRespond('resolve')}
                      style={{ flex: 1, background: 'rgba(72,187,120,0.15)', border: '1px solid var(--success)', color: 'var(--success)', borderRadius: '4px', padding: '0.6rem', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
                    >
                      <CheckCircle size={16} /> Resolve
                    </button>
                    {selected.status !== 'Investigating' && (
                      <button
                        onClick={() => handleRespond('investigate')}
                        style={{ flex: 1, background: 'rgba(236,153,75,0.1)', border: '1px solid var(--warning)', color: 'var(--warning)', borderRadius: '4px', padding: '0.6rem', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
                      >
                        <Activity size={16} /> Mark Investigating
                      </button>
                    )}
                  </div>
                </div>
              )}

              {/* Enhanced Remediation Playbook */}
              <div>
                {playbook?.error ? (
                  <div style={{ color: 'var(--danger)', fontSize: '0.85rem' }}>
                    Could not generate playbook: {playbook.error}
                    <button className="gold-button" style={{ marginLeft: '0.75rem' }} onClick={loadPlaybook} disabled={playbookLoading}>
                      {playbookLoading ? 'Generating...' : 'Retry'}
                    </button>
                  </div>
                ) : !playbook ? (
                  <button
                    className="gold-button"
                    style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
                    onClick={loadPlaybook}
                    disabled={playbookLoading}
                  >
                    <FileText size={18} /> {playbookLoading ? 'Generating...' : 'Generate Remediation Playbook (GPT-4o)'}
                  </button>
                ) : (
                  <div>
                    <div className="label-small" style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <FileText size={16} />
                      REMEDIATION PLAYBOOK (GPT-4o)
                      <span style={{ 
                        marginLeft: 'auto', 
                        fontSize: '0.7rem', 
                        color: 'var(--text-muted)',
                        background: 'rgba(255,255,255,0.05)',
                        padding: '0.2rem 0.5rem',
                        borderRadius: '10px'
                      }}>
                        {playbook.total_steps || playbook.steps?.length || 0} steps
                      </span>
                    </div>
                    
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      {playbook.steps?.map((step, i) => (
                        <div key={i} style={{ 
                          display: 'flex', 
                          gap: '1rem', 
                          alignItems: 'flex-start', 
                          background: 'rgba(255,255,255,0.02)', 
                          border: '1px solid var(--border)', 
                          borderRadius: '6px', 
                          padding: '1rem',
                          position: 'relative'
                        }}>
                          {/* Step Number */}
                          <div style={{ 
                            width: '32px', 
                            height: '32px', 
                            borderRadius: '50%', 
                            background: step.priority === 'immediate' ? 'rgba(229,62,62,0.2)' : 
                                       step.priority === 'high' ? 'rgba(236,153,75,0.2)' : 
                                       step.priority === 'medium' ? 'rgba(245,158,11,0.2)' : 
                                       'rgba(255,255,255,0.05)', 
                            border: `1px solid ${
                              step.priority === 'immediate' ? 'var(--danger)' : 
                              step.priority === 'high' ? 'var(--warning)' : 
                              step.priority === 'medium' ? 'var(--accent-gold)' : 
                              'var(--border)'
                            }`, 
                            display: 'flex', 
                            alignItems: 'center', 
                            justifyContent: 'center', 
                            fontWeight: 700, 
                            fontSize: '0.9rem', 
                            flexShrink: 0, 
                            color: step.priority === 'immediate' ? 'var(--danger)' : 
                                   step.priority === 'high' ? 'var(--warning)' : 
                                   step.priority === 'medium' ? 'var(--accent-gold)' : 
                                   'var(--text-muted)',
                            boxShadow: step.priority === 'immediate' ? '0 0 12px rgba(229,62,62,0.3)' : 'none'
                          }}>
                            {step.step}
                          </div>
                          
                          {/* Step Content */}
                          <div style={{ flex: 1 }}>
                            <div style={{ 
                              fontSize: '0.95rem', 
                              color: 'var(--text-primary)', 
                              marginBottom: '0.5rem',
                              fontWeight: 500,
                              lineHeight: 1.4
                            }}>
                              {step.action}
                            </div>
                            
                            {/* Command Block */}
                            {step.command && (
                              <div style={{ 
                                background: 'rgba(0,0,0,0.4)', 
                                border: '1px solid var(--border)', 
                                borderRadius: '4px', 
                                padding: '0.75rem', 
                                marginBottom: '0.5rem',
                                fontFamily: 'JetBrains Mono',
                                fontSize: '0.8rem',
                                color: '#e5e7eb',
                                position: 'relative',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between'
                              }}>
                                <code style={{ background: 'none', border: 'none', padding: 0, color: 'inherit' }}>
                                  {step.command}
                                </code>
                                <button
                                  aria-label="Copy command"
                                  onClick={() => copyCommand(step.command, i)}
                                  style={{
                                    background: 'rgba(255,255,255,0.1)',
                                    border: '1px solid var(--border)',
                                    borderRadius: '4px',
                                    padding: '0.25rem 0.5rem',
                                    cursor: 'pointer',
                                    display: 'flex',
                                    alignItems: 'center',
                                    transition: 'all 0.2s'
                                  }}
                                  onMouseEnter={(e) => {
                                    e.target.style.background = 'rgba(255,255,255,0.2)';
                                  }}
                                  onMouseLeave={(e) => {
                                    e.target.style.background = 'rgba(255,255,255,0.1)';
                                  }}
                                >
                                  {copiedStep === i ? <CheckCircle size={14} color="var(--success)" /> : <Copy size={14} color="var(--text-secondary)" />}
                                </button>
                              </div>
                            )}
                            
                            {/* Step Metadata */}
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem' }}>
                              <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                                <span style={{ 
                                  color: step.priority === 'immediate' ? 'var(--danger)' : 
                                         step.priority === 'high' ? 'var(--warning)' : 
                                         step.priority === 'medium' ? 'var(--accent-gold)' : 
                                         'var(--text-muted)',
                                  fontWeight: 600,
                                  textTransform: 'uppercase',
                                  letterSpacing: '0.5px'
                                }}>
                                  {step.priority}
                                </span>
                                {step.estimated_time && (
                                  <span style={{ color: 'var(--text-muted)' }}>
                                    ⏱ {step.estimated_time}
                                  </span>
                                )}
                              </div>
                              <span style={{ 
                                color: step.risk_level === 'critical' ? 'var(--danger)' : 
                                       step.risk_level === 'high' ? 'var(--warning)' : 
                                       step.risk_level === 'medium' ? 'var(--accent-gold)' : 
                                       'var(--text-muted)'
                              }}>
                                {step.risk_level} risk
                              </span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                    
                    {/* Playbook Footer */}
                    <div style={{ 
                      marginTop: '1rem', 
                      padding: '0.75rem', 
                      background: 'rgba(255,255,255,0.02)', 
                      border: '1px solid var(--border)', 
                      borderRadius: '4px',
                      fontSize: '0.8rem',
                      color: 'var(--text-muted)',
                    }}>
                      AI-generated by GPT-4o from this incident's recorded fields at {new Date(playbook.generated_at).toLocaleString()}. Review every command before running it.
                    </div>
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
