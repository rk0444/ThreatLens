import { useState, useEffect } from 'react';
import {  ChevronRight, Filter, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import ThreatGraph from '../components/ThreatGraph';
import CveDrawer from '../components/CveDrawer';
import CustomDropdown from '../components/CustomDropdown';
import { getRiskColor } from '../utils/riskScore';

const GlobalThreats = () => {
  const [cves, setCves] = useState([]);
  const [selectedCve, setSelectedCve] = useState(null);
  const [graphFocus, setGraphFocus] = useState(null);
  const [loadedQuery, setLoadedQuery] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [limit, setLimit] = useState(50);
  const [filters, setFilters] = useState({
    severity: 'All Severities',
    epssMin: 0,
    myAssetsOnly: localStorage.getItem('assetAwareFilter') === 'true',
    sortBy: 'Severity'
  });

  const sortOptions = [
    { value: 'Severity', label: 'Risk (severity)' },
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

  // Score and band come from the server (backend/services/scoring.py), so the label always
  // matches the severity filter. Bands start at whole numbers, so flooring keeps them consistent.
  const riskOf = (cve) => Math.floor(cve.risk_score ?? 0);
  const bandOf = (cve) => (cve.risk_band || 'LOW').toUpperCase();

  const formatAffectedProducts = (products) => {
    if (!products || !Array.isArray(products) || products.length === 0) {
      return <span style={{ color: 'var(--text-muted)' }}>Unknown</span>;
    }
    if (products.length === 1) return products[0];
    if (products.length <= 3) return products.join(', ');
    return `${products[0]}, ${products[1]} +${products.length - 2} more`;
  };

  // Filters shared with the graph; the table adds sort and paging. The server picks which CVEs to send.
  const filterParams = new URLSearchParams();
  if (filters.myAssetsOnly) filterParams.append('affected_only', 'true');
  if (filters.severity !== 'All Severities') filterParams.append('band', filters.severity);
  if (filters.epssMin > 0) filterParams.append('epss_pct_min', filters.epssMin);
  const filterQuery = filterParams.toString();
  const sortParam = { 'Severity': 'risk_score', 'EPSS %': 'epss', 'Published Date': 'published', 'CVSS Score': 'cvss' };
  const cveQuery = `${filterQuery}&sort=${sortParam[filters.sortBy]}&limit=${limit}`;
  // Loading until the rows for the current query have arrived (a live refresh keeps the rows visible)
  const loading = loadedQuery !== cveQuery;

  useEffect(() => {
    const load = () => fetch(`http://127.0.0.1:8000/api/cves?${cveQuery}`)
      .then(res => res.json())
      .then(data => {
        setCves(Array.isArray(data) ? data : (data.cves || []));
        setLastUpdated(new Date());
        setLoadedQuery(cveQuery);
      })
      .catch(err => {
        console.error('Fetch error:', err);
        setLoadedQuery(cveQuery);
      });
    load();

    const socket = new WebSocket('ws://127.0.0.1:8000/ws/events');
    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        // New CVEs were ingested: refetch so they go through the same filters and sort
        if (data.type === 'CVES_UPDATED') load();
      } catch (e) {
        console.error("WebSocket message error:", e);
      }
    };
    return () => socket.close();
  }, [cveQuery]);

  // Filtering happens server-side; this only adds tie-breakers to the server's order
  const sortedCves = [...cves].sort((a, b) => {
    const scoreA = a.risk_score ?? 0;
    const scoreB = b.risk_score ?? 0;
    const dateA = new Date(a.published_date || 0).getTime();
    const dateB = new Date(b.published_date || 0).getTime();
    const epssA = a.epss_score || 0;
    const epssB = b.epss_score || 0;

    if (filters.sortBy === 'Severity') {
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
            <span>LIVE — Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : '…'}</span>
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
            <span style={{ fontSize: '0.8rem' }} title="Only CVEs whose EPSS score is higher than this share of all scored CVEs">EPSS percentile ≥ {Math.round(filters.epssMin * 100)}</span>
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
          <ThreatGraph highlightedNodeId={graphFocus} filterQuery={filterQuery} />
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
                      <td colSpan="9" style={{ padding: '1rem' }}><div className="skeleton" style={{ height: '20px' }}></div></td>
                    </motion.tr>
                  ))
                ) : sortedCves.length === 0 ? (
                  <tr key="empty">
                    <td colSpan="9" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                      {filters.myAssetsOnly
                        ? 'No CVEs match your assets. Matching uses the products NVD lists for each CVE against the software your assets report.'
                        : filters.severity === 'Critical'
                          ? "No CRITICAL CVEs. Critical means a CVE on CISA's KEV list that affects one of your assets."
                          : 'No CVEs match these filters.'}
                    </td>
                  </tr>
                ) : (
                  sortedCves.map(cve => {
                    const riskScore = riskOf(cve);
                    const band = bandOf(cve);
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
                            <span className={`severity-badge severity-${band.toLowerCase()}`}>
                              {band}
                            </span>
                          </div>
                        </td>
                        <td style={{ fontFamily: 'JetBrains Mono', color: 'var(--accent-gold)' }}>{cve.cve_id}</td>
                        <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                          {cve.description}
                        </td>
                        <td>{cve.cvss_score ?? <span style={{ color: 'var(--text-muted)' }} title="NVD has not scored this CVE yet">—</span>}</td>
                        <td>
                          {cve.epss_score == null ? (
                            <span style={{ color: 'var(--text-muted)' }} title="EPSS has not scored this CVE yet">—</span>
                          ) : (
                            <>
                              {(cve.epss_score * 100).toFixed(1)}%
                              {cve.epss_percentile != null && (
                                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: '0.3rem' }}>p{Math.round(cve.epss_percentile * 100)}</span>
                              )}
                            </>
                          )}
                        </td>
                        <td>
                          {cve.cisa_kev ? (
                            <span title="On CISA's Known Exploited Vulnerabilities list" style={{ color: '#fc8181', fontWeight: 600, fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#fc8181', animation: 'pulseCritical 2s infinite' }}></div>
                              {cve.ransomware_use ? '☠ KEV · RANSOM' : '● KEV · IN THE WILD'}
                            </span>
                          ) : cve.actively_exploited ? (
                            <span title="NVD links a public exploit; no confirmed exploitation in the wild" style={{ color: '#f6ad55', fontSize: '0.8rem' }}>
                              Public exploit
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
          {!loading && cves.length >= limit && (
            <button className="gold-button" style={{ margin: '1rem auto', display: 'block' }} onClick={() => setLimit(limit + 50)}>
              Load 50 more
            </button>
          )}
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
