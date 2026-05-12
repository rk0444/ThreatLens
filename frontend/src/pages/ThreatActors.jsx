import { useState, useEffect, useRef } from 'react';
import { Search, Filter, ShieldAlert, ChevronRight, X, Flag, Shield, Tag, Target } from 'lucide-react';
import CustomDropdown from '../components/CustomDropdown';

// Helper to highlight search text
const Highlight = ({ text, highlight }) => {
  if (!highlight.trim()) return <span>{text}</span>;
  const regex = new RegExp(`(${highlight})`, 'gi');
  const parts = text.split(regex);
  return (
    <span>
      {parts.map((part, i) => 
        regex.test(part) ? (
          <mark key={i} style={{ background: 'rgba(184, 146, 42, 0.2)', color: '#B8922A', borderRadius: '2px', padding: '0 2px' }}>
            {part}
          </mark>
        ) : (
          <span key={i}>{part}</span>
        )
      )}
    </span>
  );
};

// ----- FIX 1 & 2: Full country mapping (code → flag + name) -----
const COUNTRY_MAP = {
  Russia:          { flag: '🇷🇺', name: 'Russia' },
  China:           { flag: '🇨🇳', name: 'China' },
  'United States': { flag: '🇺🇸', name: 'United States' },
  'North Korea':   { flag: '🇰🇵', name: 'North Korea' },
  Iran:            { flag: '🇮🇷', name: 'Iran' },
  Belarus:         { flag: '🇧🇾', name: 'Belarus' },
  Ukraine:         { flag: '🇺🇦', name: 'Ukraine' },
  Vietnam:         { flag: '🇻🇳', name: 'Vietnam' },
  India:           { flag: '🇮🇳', name: 'India' },
  Pakistan:        { flag: '🇵🇰', name: 'Pakistan' },
  Brazil:          { flag: '🇧🇷', name: 'Brazil' },
  Nigeria:         { flag: '🇳🇬', name: 'Nigeria' },
};

const getCountryInfo = (country) => {
  return COUNTRY_MAP[country] || { flag: '🌐', name: 'Unknown Origin' };
};

// ----- FIX 5: Motivation badge colours -----
const MOTIVATION_STYLE = {
  Financial:   { bg: 'rgba(184, 146, 42, 0.15)', border: 'rgba(184,146,42,0.4)', text: '#e0b84a' },
  Espionage:   { bg: 'rgba(26, 58, 92, 0.6)',    border: 'rgba(66,153,225,0.4)', text: '#90cdf4' },
  Sabotage:    { bg: 'rgba(74, 26, 26, 0.6)',    border: 'rgba(229,62,62,0.4)',  text: '#fc8181' },
  Ransomware:  { bg: 'rgba(74, 42, 10, 0.6)',    border: 'rgba(237,137,54,0.4)', text: '#f6ad55' },
  Hacktivism:  { bg: 'rgba(42, 26, 74, 0.6)',    border: 'rgba(159,122,234,0.4)', text: '#b794f4' },
};

const getMotivationStyle = (motivation) => {
  for (const [key, style] of Object.entries(MOTIVATION_STYLE)) {
    if (motivation?.toLowerCase().includes(key.toLowerCase())) return style;
  }
  return { bg: 'rgba(255,255,255,0.05)', border: 'rgba(255,255,255,0.1)', text: 'var(--text-muted)' };
};

const ThreatActors = () => {
  const [actors, setActors]           = useState([]);
  const [loading, setLoading]         = useState(true);
  const [searchTerm, setSearchTerm]   = useState('');
  const [filter, setFilter]           = useState('All');
  const [selectedActor, setSelectedActor] = useState(null);
  const [isFocused, setIsFocused]     = useState(false);
  const [suggestions, setSuggestions] = useState([]);
  const searchRef = useRef(null);

  const loadActorDetails = (id) => {
    fetch(`http://127.0.0.1:8000/api/threat-actors/${id}`)
      .then(res => res.json())
      .then(data => setSelectedActor(data))
      .catch(err => console.error(err));
  };

  useEffect(() => {
    fetch('http://127.0.0.1:8000/api/threat-actors')
      .then(res => res.json())
      .then(data => { setActors(data); setLoading(false); })
      .catch(err => { console.error('Fetch error:', err); setLoading(false); });

    // Keyboard shortcuts
    const handleKeyDown = (e) => {
      if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
        e.preventDefault();
        searchRef.current?.focus();
      }
      if (e.key === 'Escape') {
        setSearchTerm('');
        searchRef.current?.blur();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const filteredActors = actors.filter(actor => {
    const matchesFilter = filter === 'All' || actor.motivation?.toLowerCase().includes(filter.toLowerCase());
    if (!matchesFilter) return false;

    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const country = getCountryInfo(actor.country);
      return actor.name.toLowerCase().includes(term) ||
             country.name.toLowerCase().includes(term) ||
             (actor.country && actor.country.toLowerCase().includes(term)) ||
             (actor.aliases && actor.aliases.join(' ').toLowerCase().includes(term)) ||
             (actor.mitre_id && actor.mitre_id.toLowerCase().includes(term)) ||
             (actor.motivation && actor.motivation.toLowerCase().includes(term));
    }
    return true;
  });

  // Handle Suggestions
  useEffect(() => {
    if (!searchTerm || searchTerm.length < 1) {
      setSuggestions([]);
      return;
    }
    const term = searchTerm.toLowerCase();
    const results = [];
    
    // Check Groups
    actors.forEach(a => {
      if (a.name.toLowerCase().includes(term) && results.length < 5) {
        if (!results.find(r => r.text === a.name))
          results.push({ text: a.name, category: 'Group', icon: Shield, value: a.name });
      }
      if (a.mitre_id?.toLowerCase().includes(term) && results.length < 5) {
        if (!results.find(r => r.text === a.mitre_id))
          results.push({ text: a.mitre_id, category: 'MITRE ID', icon: Tag, value: a.mitre_id });
      }
      const country = getCountryInfo(a.country);
      if (country.name.toLowerCase().includes(term) && results.length < 5) {
        if (!results.find(r => r.text === country.name))
          results.push({ text: country.name, category: 'Country', icon: Flag, value: country.name });
      }
    });

    setSuggestions(results.slice(0, 5));
  }, [searchTerm, actors]);

  const motivationOptions = [
    { value: 'All', label: 'All' },
    { value: 'Espionage', label: 'Espionage' },
    { value: 'Financial', label: 'Financial' },
    { value: 'Sabotage', label: 'Sabotage' },
    { value: 'Ransomware', label: 'Ransomware' },
    { value: 'Hacktivism', label: 'Hacktivism' },
  ];

  return (
    <div className="page-container" style={{ padding: '24px', position: 'relative' }}>

      {/* ── Page Header ── */}
      <div className="top-header" style={{ display: 'flex', alignItems: 'center', marginBottom: '2.5rem' }}>
        {/* 1. Title */}
        <div style={{ flexShrink: 0 }}>
          <div className="label-small">MITRE ATT&CK CTI</div>
          <h1 style={{ margin: 0 }}>Threat <span className="italic-serif">Actors</span></h1>
        </div>

        {/* 2. Live Badge */}
        <div className="status-badge" style={{ marginLeft: '16px', flexShrink: 0, height: 'fit-content', marginTop: '14px' }}>
          <div className="status-dot"></div>
          <span>LIVE — Tracking {actors.length} APTs &amp; Syndicates</span>
        </div>

        {/* 3. Spacer */}
        <div style={{ flexGrow: 1 }} />

        {/* 4. Search Bar (360px) */}
        <div style={{ width: '360px', flexShrink: 0, position: 'relative' }}>
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            height: '48px', 
            background: '#1B2E4B',
            border: `1px solid ${isFocused ? '#B8922A' : 'rgba(184, 146, 42, 0.3)'}`,
            borderRadius: '8px',
            boxShadow: isFocused ? '0 0 0 3px rgba(184, 146, 42, 0.15)' : 'none',
            transition: 'all 200ms ease',
            position: 'relative'
          }}>
            <Search size={18} color="#B8922A" style={{ marginLeft: '16px', flexShrink: 0 }} />
            <div style={{ width: '1px', height: '24px', background: 'rgba(184, 146, 42, 0.2)', margin: '0 12px' }} />
            <input
              ref={searchRef}
              type="text"
              placeholder="Search threat actors..."
              value={searchTerm}
              onFocus={() => setIsFocused(true)}
              onBlur={() => setTimeout(() => setIsFocused(false), 200)}
              onChange={e => setSearchTerm(e.target.value)}
              style={{ 
                background: 'transparent', 
                border: 'none', 
                color: '#F0F4F8', 
                outline: 'none', 
                flexGrow: 1,
                fontSize: '14px',
                paddingRight: '16px'
              }}
            />
            
            {/* Right Side Search Controls */}
            <div style={{ display: 'flex', alignItems: 'center', height: '100%', flexShrink: 0 }}>
              {!searchTerm && !isFocused && (
                <div style={{ padding: '0 16px' }}>
                  <div style={{ padding: '2px 8px', background: 'rgba(0,0,0,0.3)', borderRadius: '4px', fontSize: '12px', color: 'rgba(184, 146, 42, 0.6)', border: '1px solid rgba(184, 146, 42, 0.2)' }}>
                    /
                  </div>
                </div>
              )}

              {searchTerm && (
                <div style={{ display: 'flex', alignItems: 'center', height: '100%', animation: 'fadeIn 0.2s' }}>
                  {/* Results Counter */}
                  <div style={{ width: '1px', height: '20px', background: 'rgba(184, 146, 42, 0.2)' }} />
                  <div style={{ color: '#8BA3BF', fontSize: '12px', padding: '0 12px', whiteSpace: 'nowrap' }}>
                    {filteredActors.length} of {actors.length}
                  </div>
                  
                  {/* Clear Button */}
                  <div style={{ width: '1px', height: '20px', background: 'rgba(184, 146, 42, 0.2)' }} />
                  <button 
                    onClick={() => setSearchTerm('')}
                    style={{ background: 'transparent', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', padding: '0 12px' }}
                  >
                    <X size={16} color="#B8922A" />
                  </button>
                </div>
              )}
            </div>

            {/* Suggestions Dropdown */}
            {isFocused && suggestions.length > 0 && (
              <div style={{
                position: 'absolute',
                top: 'calc(100% + 8px)',
                left: 0,
                right: 0,
                background: '#1B2E4B',
                border: '1px solid rgba(184, 146, 42, 0.4)',
                borderRadius: '6px',
                boxShadow: '0 8px 24px rgba(0, 0, 0, 0.4)',
                zIndex: 1000,
                padding: '4px 0'
              }}>
                {suggestions.map((s, i) => (
                  <div 
                    key={i} 
                    onClick={() => { setSearchTerm(s.value); setIsFocused(false); }}
                    style={{ 
                      padding: '10px 16px', 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: '12px', 
                      cursor: 'pointer',
                      transition: 'background 0.2s'
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(184, 146, 42, 0.1)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <s.icon size={14} color="#B8922A" />
                    <div style={{ flex: 1, fontSize: '13px' }}>
                      <Highlight text={s.text} highlight={searchTerm} />
                    </div>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>{s.category}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* 5. Filter Dropdown (180px) */}
        <div style={{ width: '180px', flexShrink: 0, marginLeft: '12px' }}>
          <CustomDropdown 
            options={motivationOptions}
            value={filter}
            onChange={(val) => setFilter(val)}
          />
        </div>
      </div>

      {/* ── Card Grid ── */}
      {filteredActors.length === 0 && !loading ? (
        <div style={{ textAlign: 'center', padding: '100px 0', opacity: 0.8 }}>
          <Search size={48} color="var(--text-muted)" style={{ marginBottom: '1rem', opacity: 0.3 }} />
          <h3 style={{ color: 'var(--text-secondary)' }}>No threat actors found matching "{searchTerm}"</h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Try searching by name, country, or MITRE ID.</p>
        </div>
      ) : (
        <div className="actor-grid" style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
          gap: '16px',
        }}>
          <style>{`
            @media (min-width: 1400px) { .actor-grid { grid-template-columns: repeat(3, 1fr) !important; } }
            @media (min-width: 900px) and (max-width: 1399px) { .actor-grid { grid-template-columns: repeat(2, 1fr) !important; } }
            @media (max-width: 899px) { .actor-grid { grid-template-columns: 1fr !important; } }
            .actor-card { border: 1px solid rgba(184,146,42,0.15); transition: border-color 200ms ease, box-shadow 200ms ease; }
            .actor-card:hover { border-color: rgba(184,146,42,0.5) !important; box-shadow: 0 0 16px rgba(184,146,42,0.1) !important; }
            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
          `}</style>

          {loading ? (
            [1,2,3,4,5,6].map(i => (
              <div key={i} className="glass-panel skeleton" style={{ height: '160px', borderRadius: '6px' }} />
            ))
          ) : filteredActors.map(actor => {
            const { flag, name: countryName } = getCountryInfo(actor.country);
            const motStyle = getMotivationStyle(actor.motivation);
            const hasCves  = actor.cve_count > 0;
            const techName = actor.latest_technique
              ? actor.latest_technique.length > 20
                ? actor.latest_technique.slice(0, 19) + '…'
                : actor.latest_technique
              : null;

            return (
              <div
                key={actor.id}
                className="glass-panel actor-card"
                style={{
                  cursor: 'pointer',
                  minHeight: '160px',
                  display: 'flex',
                  flexDirection: 'column',
                  padding: 0,
                  overflow: 'hidden',
                }}
                onClick={() => loadActorDetails(actor.id)}
              >
                {/* ── ROW 1: Name + flag + motivation badge ── */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '16px 16px 12px 16px' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      fontWeight: 700,
                      fontSize: '1rem',
                      color: 'var(--accent-gold)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      flexWrap: 'wrap',
                    }}>
                      <Highlight text={actor.name} highlight={searchTerm} />
                      <span style={{ fontSize: '1.1rem' }}>{flag}</span>
                      <span style={{ fontWeight: 400, fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        <Highlight text={countryName} highlight={searchTerm} />
                      </span>
                    </div>
                  </div>
                  <span style={{
                    flexShrink: 0,
                    marginLeft: '8px',
                    background: motStyle.bg,
                    border: `1px solid ${motStyle.border}`,
                    color: motStyle.text,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '0.65rem',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.6px',
                    whiteSpace: 'nowrap',
                  }}>
                    {actor.motivation || 'Unknown'}
                  </span>
                </div>

                {/* ── DIVIDER ── */}
                <div style={{ height: '1px', background: 'rgba(184,146,42,0.15)', margin: '0 16px' }} />

                {/* ── ROW 2: Stats ── */}
                <div style={{ display: 'flex', padding: '12px 16px', gap: '1rem', flex: 1 }}>
                  <div style={{ flex: '0 0 40%' }}>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>Linked CVEs</div>
                    <div style={{
                      fontSize: '1.5rem',
                      fontWeight: 700,
                      fontFamily: 'DM Serif Display',
                      color: hasCves ? 'var(--accent-gold)' : 'var(--text-muted)',
                      lineHeight: 1,
                    }}>
                      {actor.cve_count ?? 0}
                    </div>
                  </div>
                  <div style={{ width: '1px', background: 'rgba(184,146,42,0.15)', alignSelf: 'stretch' }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>Latest Technique</div>
                    {techName ? (
                      <>
                        <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {techName}
                        </div>
                        <div style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem', color: 'var(--accent-gold)', marginTop: '2px' }}>
                          {actor.latest_technique_id}
                        </div>
                      </>
                    ) : (
                      <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Not mapped</div>
                    )}
                  </div>
                </div>

                {/* ── DIVIDER ── */}
                <div style={{ height: '1px', background: 'rgba(184,146,42,0.15)', margin: '0 16px' }} />

                {/* ── ROW 3: MITRE ID + Active ── */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 16px 14px 16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <ShieldAlert size={13} color="var(--danger)" />
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      MITRE{' '}
                      <span style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)' }}>
                        <Highlight text={actor.mitre_id || ''} highlight={searchTerm} />
                      </span>
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.78rem', color: 'var(--success)' }}>
                    <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--success)' }} />
                    Active
                    <ChevronRight size={13} color="var(--text-muted)" />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Detail Drawer (unchanged structure) ── */}
      {selectedActor && (
        <div className="drawer-overlay" onClick={() => setSelectedActor(null)}>
          <div className="drawer" onClick={e => e.stopPropagation()} style={{ width: '600px' }}>
            <div className="drawer-header">
              <div>
                <div className="label-small">{selectedActor.group.mitre_id}</div>
                <h2>
                  {selectedActor.group.name}{' '}
                  {getCountryInfo(selectedActor.group.country).flag}
                </h2>
              </div>
              <button className="close-btn" onClick={() => setSelectedActor(null)}>✕</button>
            </div>

            <div className="drawer-content">
              <div style={{ display: 'flex', gap: '1rem', marginBottom: '2rem', flexWrap: 'wrap' }}>
                <div style={{ background: 'rgba(255,255,255,0.05)', padding: '0.5rem 1rem', borderRadius: '4px' }}>
                  <div className="label-small" style={{ fontSize: '0.7rem' }}>Origin</div>
                  <div style={{ fontWeight: 600 }}>
                    {getCountryInfo(selectedActor.group.country).flag} {selectedActor.group.country}
                  </div>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.05)', padding: '0.5rem 1rem', borderRadius: '4px' }}>
                  <div className="label-small" style={{ fontSize: '0.7rem' }}>Motivation</div>
                  <div style={{ fontWeight: 600 }}>{selectedActor.group.motivation}</div>
                </div>
              </div>

              <div className="description-box" style={{ marginBottom: '2rem' }}>
                <div className="label-small">Description</div>
                <p style={{ lineHeight: 1.6 }}>{selectedActor.group.description || 'No detailed description available.'}</p>
                {selectedActor.group.aliases?.length > 0 && (
                  <div style={{ marginTop: '1rem', color: 'var(--text-muted)' }}>
                    <strong>Known Aliases:</strong> {selectedActor.group.aliases.join(', ')}
                  </div>
                )}
              </div>

              <div className="asset-section" style={{ marginBottom: '2rem' }}>
                <div className="label-small">Known Exploited Vulnerabilities</div>
                {selectedActor.linked_cves && selectedActor.linked_cves.length > 0 ? (
                  <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1rem', fontSize: '0.9rem' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                        <th style={{ paddingBottom: '0.5rem' }}>CVE</th>
                        <th style={{ paddingBottom: '0.5rem' }}>Technique</th>
                        <th style={{ paddingBottom: '0.5rem' }}>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedActor.linked_cves.map((link, idx) => (
                        <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                          <td style={{ padding: '0.75rem 0', fontFamily: 'JetBrains Mono', color: 'var(--accent-gold)' }}>{link.cve_id}</td>
                          <td style={{ padding: '0.75rem 0', fontSize: '0.85rem' }}>{link.technique_id || '—'}</td>
                          <td style={{ padding: '0.75rem 0' }}>
                            <span className={`severity-badge ${link.confidence === 'confirmed' ? 'severity-critical' : 'severity-medium'}`}>
                              {link.confidence?.toUpperCase()}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p style={{ color: 'var(--text-muted)', marginTop: '0.5rem' }}>No direct CVE linkages identified in MITRE database for this group.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatActors;
