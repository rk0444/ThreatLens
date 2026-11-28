import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Globe, Shield, AlertTriangle, Settings, PanelLeftClose, PanelLeftOpen, Users, Bot, Map, FileSearch, ShieldCheck } from 'lucide-react';

const NAV_ITEMS = [
  { name: 'Overview',       icon: LayoutDashboard, path: '/' },
  { name: 'Global Threats', icon: Globe,           path: '/global' },
  { name: 'Attack Map',     icon: Map,             path: '/attackmap' },
  { name: 'Threat Actors',  icon: Users,           path: '/actors' },
  { name: 'Endpoints',      icon: Shield,          path: '/endpoints' },
  { name: 'Incidents',      icon: AlertTriangle,   path: '/incidents' },
  { name: 'AI Copilot',     icon: Bot,             path: '/copilot' },
  { name: 'IOC Hunter',     icon: FileSearch,      path: '/ioc' },
  { name: 'Settings',       icon: Settings,        path: '/settings' },
];

const Sidebar = () => {
  const [isExpanded, setIsExpanded] = useState(true);
  return (
    <aside className={`sidebar ${isExpanded ? 'expanded' : 'collapsed'}`}>
      <div className="brand">
        <ShieldCheck size={20} aria-hidden="true" />
        <span className="brand-text">ThreatLens</span>
      </div>
      <nav className="sidebar-nav" aria-label="Main">
        {NAV_ITEMS.map(item => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            title={item.name}
          >
            <item.icon size={18} className="nav-icon" aria-hidden="true" />
            <span className="nav-text">{item.name}</span>
          </NavLink>
        ))}
      </nav>
      <button type="button" className="expand-toggle" onClick={() => setIsExpanded(!isExpanded)} aria-expanded={isExpanded}>
        {isExpanded ? <PanelLeftClose size={18} aria-hidden="true" /> : <PanelLeftOpen size={18} aria-hidden="true" />}
        <span className="nav-text">{isExpanded ? 'Collapse' : <span className="sr-only">Expand sidebar</span>}</span>
      </button>
    </aside>
  );
};

export default Sidebar;
