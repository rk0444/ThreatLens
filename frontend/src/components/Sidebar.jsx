import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Globe, Shield, AlertTriangle, Settings, ChevronLeft, ChevronRight, Users } from 'lucide-react';

const Sidebar = () => {
  const [isExpanded, setIsExpanded] = useState(true);

  const navItems = [
    { name: 'Overview',      icon: LayoutDashboard, path: '/' },
    { name: 'Global Threats', icon: Globe,           path: '/global' },
    { name: 'Threat Actors', icon: Users,            path: '/actors' },
    { name: 'Endpoints',     icon: Shield,           path: '/endpoints' },
    { name: 'Incidents',     icon: AlertTriangle,    path: '/incidents' },
    { name: 'Settings',      icon: Settings,         path: '/settings' },
  ];

  return (
    <div className={`sidebar ${isExpanded ? 'expanded' : 'collapsed'}`}>
      <div className="sidebar-header">
        <button className="expand-toggle" onClick={() => setIsExpanded(!isExpanded)}>
          {isExpanded ? <ChevronLeft size={20} /> : <ChevronRight size={20} />}
        </button>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
          >
            <item.icon size={24} className="nav-icon" />
            {isExpanded && <span className="nav-text">{item.name}</span>}
          </NavLink>
        ))}
      </nav>

    </div>
  );
};

export default Sidebar;
