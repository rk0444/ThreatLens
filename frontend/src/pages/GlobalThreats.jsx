import { useState, useEffect } from 'react';
import {  ChevronRight, Filter, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import ThreatGraph from '../components/ThreatGraph';
import CveDrawer from '../components/CveDrawer';
import CustomDropdown from '../components/CustomDropdown';

const GlobalThreats = () => {
  const [cves, setCves] = useState([]);
  const [selectedCve, setSelectedCve] = useState(null);
  const [selectedActors, setSelectedActors] = useState([]);
  const [graphFocus, setGraphFocus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    severity: 'All Severities',
    epssMin: 0,
    myAssetsOnly: localStorage.getItem('assetAwareFilter') === 'true',
    sortBy: 'Severity'
  });

  const sortOptions = [
    { value: 'Severity', label: 'Severity' },
    { value: 'Risk Score', label: 'Risk Score' },
    { value: 'EPSS %', label: 'EPSS %' },
    { value: 'Published Date', label: 'Published Date' },
    { value: 'CVSS Score', label: 'CVSS Score' },
  ];

  const severityOptions = [
  { value: 'All Severities', label: 'All Severities' },
  { value: 'Critical', label: 'Critical' },
  { value: 'High', label: 'High' },
  { value: 'Medium', label: 'Medium' },
  { value: 'Low', label: 'Low' },
];

  const getSeverityTier = (score) => {
    if (score >= 86) return { label: 'CRITICAL', className: 'severity-critical' };
    if (score >= 61) return { label: 'HIGH', className: 'severity-high' };
    if (score >= 31) return { label: 'MEDIUM', className: 'severity-medium' };
    if (score >= 1) return { label: 'LOW', className: 'severity-low' };
    return { label: 'INFO', className: 'severity-info' };
  };

  const formatAffectedProducts = (products) => {
    if (!products || !Array.isArray(products) || products.length === 0) {
      return <span style={{ color: 'var(--text-muted)' }}>Unknown</span>;
    }
    if (products.length === 1) return products[0];
    if (products.length <= 3) return products.join(', ');
    return `${products[0]}, ${products[1]} +${products.length - 2} more`;
  };

  const fetchCves = () => {
    setLoading(true);
    const params = new URLSearchParams();
    if (filters.myAssetsOnly) params.append('affected_only', 'true');
    if (filters.severity !== 'All Severities') params.append('severity', filters.severity === 'Critical' ? '9' : '7');

    fetch(`http://127.0.0.1:8000/api/cves?${params.toString()}`)
      .then(res => res.json())
      .then(data => {
        console.log(data);
        setCves(Array.isArray(data) ? data : (data.cves || []));
        setLoading(false);
      })
      .catch(err => {
        console.error('Fetch error:', err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchCves();

    const socket = new WebSocket('ws://127.0.0.1:8000/ws/events');
    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'NEW_CVE' || data.type === 'OSINT_ALERT') {
          // If we are in asset-aware mode, only add if it affects an asset
          if (filters.myAssetsOnly && !data.data.asset_affected) return;
          setCves(prev => Array.isArray(prev) ? [data.data, ...prev] : [data.data]);
        }
      } catch (e) {
        console.error("WebSocket message error:", e);
      }
    };
    return () => socket.close();
  }, [filters.myAssetsOnly, filters.severity]);

  useEffect(() => {
    if (selectedCve) {
      fetch(`http://127.0.0.1:8000/api/cves/${selectedCve.cve_id}/threat-actors`)
        .then(res => res.json())
        .then(data => setSelectedActors(data))
        .catch(err => console.error(err));
    } else {
      setSelectedActors([]);
    }
  }, [selectedCve]);

  const getRiskColor = (score) => {
  if (score >= 86) return 'var(--danger)';   // CRITICAL
  if (score >= 61) return 'var(--warning)';  // HIGH
  if (score >= 31) return 'var(--accent-gold)'; // MEDIUM
  return 'var(--success)';                   // LOW
};

  const getRiskScore = (cve, asset = null) => {
  // 0.25 × CVSS (0–10 normalized to 0–100)
  const cvssComponent = ((cve.cvss_score || 0) / 10) * 100 * 0.25;

  // 0.20 × EPSS (already 0–1, normalize to 0–100)
  const epssComponent = (cve.epss_score || 0) * 100 * 0.20;

  // 0.15 × KEV (binary: on CISA KEV list or not)
  const kevComponent = cve.cisa_kev ? 100 * 0.15 : 0;

  // 0.10 × Exploit (public exploit available)
  const exploitComponent = cve.actively_exploited ? 100 * 0.10 : 0;

  // 0.10 × Asset (does it affect your inventory)
  const assetComponent = cve.asset_affected ? 100 * 0.10 : 0;

  // 0.05 × Exposure (how many assets affected)
  const exposureComponent = (() => {
    const count = cve.affected_asset_count || 0;
    if (!cve.asset_affected) return 0;
    if (count >= 10) return 100 * 0.05;
    if (count >= 5)  return 75  * 0.05;
    if (count >= 2)  return 50  * 0.05;
    return            25  * 0.05;
  })();

  // 0.05 × Threat (ransomware or APT association)
  const threatComponent = cve.ransomware_use ? 100 * 0.05 : 0;

  // 0.05 × Patch (no patch available = higher risk)
  const patchComponent = cve.patch_available === false ? 100 * 0.05 : 0;

  // 0.05 × Temporal (recency — published within last 30 days)
  const temporalComponent = (() => {
    const days = (Date.now() - new Date(cve.published_date || 0).getTime()) 
                 / (1000 * 60 * 60 * 24);
    if (days <= 7)  return 100 * 0.05;
    if (days <= 30) return 60  * 0.05;
    if (days <= 90) return 30  * 0.05;
    return 0;
  })();

  return Math.min(100, Math.round(
    cvssComponent + epssComponent + kevComponent + exploitComponent +
    assetComponent + exposureComponent + threatComponent + 
    patchComponent + temporalComponent
  ));
};

  const filteredCves = cves.filter(cve => {
    if (filters.severity !== 'All Severities') {
      const score = getRiskScore(cve);
      const tier = getSeverityTier(score).label;
      if (tier !== filters.severity.toUpperCase()) return false;
    }
    if (cve.epss_score < filters.epssMin) return false;
    if (filters.myAssetsOnly && !cve.asset_affected) return false;
    return true;
  });

  const sortedCves = [...filteredCves].sort((a, b) => {
    const scoreA = getRiskScore(a);
    const scoreB = getRiskScore(b);
    const dateA = new Date(a.published_date || 0).getTime();
    const dateB = new Date(b.published_date || 0).getTime();
    const epssA = a.epss_score || 0;
    const epssB = b.epss_score || 0;

    if (filters.sortBy === 'Severity' || filters.sortBy === 'Risk Score') {
      if (scoreA !== scoreB) return scoreB - scoreA;
      return dateB - dateA;
    }
    if (filters.sortBy === 'EPSS %') {
      if (epssA !== epssB) return epssB - epssA;
      return scoreB - scoreA;
    }
    if (filters.sortBy === 'Published Date') {
      if (dateA !== dateB) return dateB - dateA;
      return scoreB - scoreA;
    }
    if (filters.sortBy === 'CVSS Score') {
      const cvssA = a.cvss_score || 0;
      const cvssB = b.cvss_score || 0;
      if (cvssA !== cvssB) return cvssB - cvssA;
      return dateB - dateA;
    }
    return 0;
  });

  return (
    <div className="page-container" style={{ padding: '24px', position: 'relative' }}>
      <div className="top-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '2rem' }}>
        <div>
          <div className="label-small">Global Intelligence</div>
          <h1>Global <span className="italic-serif">Threats</span></h1>
          <div className="status-badge" style={{ marginTop: '0.5rem', width: 'fit-content' }}>
            <div className="status-dot"></div>
            <span>LIVE — Last updated: {new Date().toLocaleTimeString()}</span>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '0.75rem 1.5rem', display: 'flex', gap: '1.5rem', alignItems: 'center', overflow: 'visible', zIndex: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span className="label-small" style={{ marginBottom: 0 }}>Sort By</span>
            <CustomDropdown 
              options={sortOptions}
              value={filters.sortBy}
              onChange={(val) => setFilters({...filters, sortBy: val})}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Filter size={16} color="var(--text-secondary)" />
            <CustomDropdown 
              options={severityOptions}
              value={filters.severity}
              onChange={(val) => setFilters({...filters, severity: val})}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={16} color="var(--text-secondary)" />
            <span style={{ fontSize: '0.8rem' }}>EPSS Min: {filters.epssMin}</span>
            <input 
              type="range" min="0" max="1" step="0.1" 
              value={filters.epssMin}
              onChange={(e) => setFilters({...filters, epssMin: parseFloat(e.target.value)})}
            />
          </div>
          <label style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input 
              type="checkbox" 
              checked={filters.myAssetsOnly}
              onChange={(e) => {
                const val = e.target.checked;
                setFilters({...filters, myAssetsOnly: val});
                localStorage.setItem('assetAwareFilter', val);
              }}
              style={{ cursor: 'pointer' }}
            />
            <span style={{ color: filters.myAssetsOnly ? 'var(--accent-gold)' : 'var(--text-secondary)', fontWeight: filters.myAssetsOnly ? 600 : 400 }}>
              Asset-Aware Filtering
            </span>
          </label>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '2rem' }}>
        <div style={{ position: 'relative' }}>
          <ThreatGraph highlightedNodeId={graphFocus} />
          {graphFocus && (
            <button 
              onClick={() => setGraphFocus(null)}
              style={{
                position: 'absolute',
                top: '15px',
                right: '15px',
                background: 'rgba(255,255,255,0.1)',
                border: '1px solid var(--border)',
                color: 'var(--text-primary)',
                padding: '0.5rem 1rem',
                borderRadius: '4px',
                cursor: 'pointer',
                zIndex: 20
              }}
            >
              Clear Focus
            </button>
          )}
        </div>

        <div className="glass-panel" style={{ overflow: 'hidden' }}>
          <table className="threat-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
                <th style={{ padding: '1rem' }}>RISK</th>
                <th>CVE ID</th>
                <th>DESCRIPTION</th>
                <th>CVSS</th>
                <th>EPSS %</th>
                <th>EXPLOITED</th>
                <th>AFFECTED</th>
                <th>PUBLISHED</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <AnimatePresence>
                {loading ? (
                  [1,2,3,4,5].map(i => (
                    <motion.tr key={`loading-${i}`} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                      <td colSpan="8" style={{ padding: '1rem' }}><div className="skeleton" style={{ height: '20px' }}></div></td>
                    </motion.tr>
                  ))
                ) : (
                  sortedCves.map(cve => {
                    const riskScore = getRiskScore(cve);
                    const tier = getSeverityTier(riskScore);
                    return (
                      <motion.tr 
                        key={cve.id} 
                        initial={{ opacity: 0, y: -20, backgroundColor: 'rgba(184, 146, 42, 0.5)' }}
                        animate={{ opacity: 1, y: 0, backgroundColor: 'transparent' }}
                        exit={{ opacity: 0, scale: 0.9 }}
                        transition={{ duration: 0.5 }}
                        className="table-row" 
                        onClick={() => setSelectedCve(cve)}
                        style={{ borderBottom: '1px solid rgba(184, 146, 42, 0.05)', cursor: 'pointer' }}
                      >
                        <td style={{ padding: '1rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                            <div className="risk-badge" style={{ borderColor: getRiskColor(riskScore) }}>
                              {riskScore}
                            </div>
                            <span className={`severity-badge ${tier.className}`}>
                              {tier.label}
                            </span>
                          </div>
                        </td>
                        <td style={{ fontFamily: 'JetBrains Mono', color: 'var(--accent-gold)' }}>{cve.cve_id}</td>
                        <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                          {cve.description}
                        </td>
                        <td>{cve.cvss_score}</td>
                        <td>{(cve.epss_score * 100).toFixed(1)}%</td>
                        <td>
                          {cve.actively_exploited ? (
                            <span style={{ color: '#fc8181', fontWeight: 600, fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#fc8181', animation: 'pulseCritical 2s infinite' }}></div>
                              {cve.ransomware_use ? '☠ RANSOM' : '● LIVE'}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>—</span>
                          )}
                        </td>
                        <td style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {formatAffectedProducts(cve.affected_products)}
                        </td>
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{new Date(cve.published_date).toLocaleDateString()}</td>
                        <td><ChevronRight size={18} color="var(--text-muted)" /></td>
                      </motion.tr>
                    );
                  })
                )}
              </AnimatePresence>
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Drawer */}
      <CveDrawer 
        cve={selectedCve} 
        onClose={() => setSelectedCve(null)} 
        footer={
          <button 
            className="gold-button" 
            style={{ width: '100%' }}
            onClick={() => {
              setGraphFocus(selectedCve.cve_id);
              setSelectedCve(null);
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
          >
            View in Knowledge Graph
          </button>
        }
      />


    </div>
  );
};

export default GlobalThreats;
