import React from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { 
  Shield, 
  LayoutDashboard, 
  Activity, 
  AlertTriangle, 
  ShieldAlert, 
  PlayCircle,
  Settings,
  FileText,
} from 'lucide-react';

const Sidebar = () => {
  const { user, hasRole } = useAuth();
  const analystBase = user?.role === 'ANALYST' ? '/analyst' : '';

  const allNavItems = [
    { path: `${analystBase}/dashboard`, label: user?.role === 'ANALYST' ? 'SOC Overview' : 'Dashboard', icon: LayoutDashboard, roles: ['ADMIN', 'ANALYST'] },
    { path: `${analystBase}/detections`, label: user?.role === 'ANALYST' ? 'Threat Detection' : 'AI Detections', icon: Activity, roles: ['ADMIN', 'ANALYST'] },
    { path: `${analystBase}/alerts`, label: 'Threat Alerts', icon: AlertTriangle, roles: ['ADMIN', 'ANALYST'] },
    { path: `${analystBase}/incidents`, label: 'Incidents', icon: ShieldAlert, roles: ['ADMIN', 'ANALYST'] },
    { path: `${analystBase}/response-actions`, label: 'Simulated Responses', icon: PlayCircle, roles: ['ADMIN', 'ANALYST'] },
    { path: `${analystBase}/audit-logs`, label: 'Audit Logs', icon: FileText, roles: ['ADMIN', 'ANALYST'] },
    { path: `${analystBase}/settings`, label: 'Settings & Model', icon: Settings, roles: ['ADMIN', 'ANALYST'] },
  ];

  const visibleNavItems = allNavItems.filter((item) => hasRole(item.roles));

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo-icon">
          <Shield size={22} />
        </div>
        <div>
          <div className="sidebar-title">CYBER GUARD</div>
          <div className="sidebar-subtitle">AI SOC Platform v1.0</div>
        </div>
      </div>
      <nav className="sidebar-nav">
        {visibleNavItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
};

export default Sidebar;
