import { useState, useEffect } from 'react';

const API = 'http://127.0.0.1:8000';

// /api/health keys, in display order
const FEEDS = [
  ['nvd', 'NVD'], ['otx', 'OTX'], ['abuseipdb', 'AbuseIPDB'], ['virustotal', 'VirusTotal'], ['ai', 'GPT-4o'], ['agent', 'Agent'],
];
const OK_STATES = ['Live', 'Active', 'Ready', 'Online'];

const dotClass = (status) => (OK_STATES.includes(status) ? 'ok' : status === 'Delayed' ? 'delayed' : 'down');

const formatClock = (date) =>
  date.toLocaleString(undefined, { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false, timeZoneName: 'short' });

const TopBar = () => {
  const [time, setTime] = useState(new Date());
  const [health, setHealth] = useState(null);
  const [unreachable, setUnreachable] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 15000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    let alive = true;
    const load = () => fetch(`${API}/api/health`)
      .then(res => (res.ok ? res.json() : Promise.reject(res.status)))
      .then(data => { if (alive) { setHealth(data); setUnreachable(false); } })
      .catch(() => { if (alive) setUnreachable(true); });
    load();
    const timer = setInterval(load, 60000);
    return () => { alive = false; clearInterval(timer); };
  }, []);

  return (
    <header className="topbar">
      <ul className="feed-list" aria-label="Data feed status">
        {unreachable ? (
          <li className="feed"><span className="feed-dot down" aria-hidden="true" /><span className="feed-name">Backend unreachable</span></li>
        ) : !health ? (
          <li className="feed">Checking data feeds…</li>
        ) : FEEDS.map(([key, label]) => {
          const feed = health[key];
          if (!feed) return null;
          return (
            <li key={key} className="feed" title={`${label}: ${feed.status} (${feed.detail})`}>
              <span className={`feed-dot ${dotClass(feed.status)}`} aria-hidden="true" />
              <span className="feed-name">{label}</span>
              <span className="feed-state">{feed.status}</span>
            </li>
          );
        })}
      </ul>
      <time className="topbar-clock" dateTime={time.toISOString()}>{formatClock(time)}</time>
    </header>
  );
};

export default TopBar;
