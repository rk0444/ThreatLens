import { useState, useEffect } from 'react';
import { Bell, ShieldCheck } from 'lucide-react';

const TopBar = () => {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const formatUTC = (date) => {
    return date.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  };

  return (
    <header className="topbar">
      <div className="topbar-left">
        <div className="logo">
          <ShieldCheck className="logo-icon" />
          <span className="logo-text">Threat<span className="logo-accent">Lens</span> <span className="version">V2.0</span></span>
        </div>
      </div>

      <div className="topbar-center">
        <div className="status-badge">
          <div className="status-dot"></div>
          <span>SYSTEM ACTIVE</span>
        </div>
      </div>

      <div className="topbar-right">
        <div className="utc-clock">{formatUTC(time)}</div>
        <button className="notification-btn">
          <Bell size={20} />
          <div className="notification-dot"></div>
        </button>
      </div>

    </header>
  );
};

export default TopBar;
