import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity,
  CircleUserRound,
  FileCheck2,
  History,
  LayoutDashboard,
  Search,
  Shield,
} from 'lucide-react';

const navigation = [
  { path: '/user/dashboard', label: 'Overview', icon: LayoutDashboard },
  { path: '/user/check-website', label: 'Check Website', icon: Search },
  { path: '/user/results', label: 'My results', icon: FileCheck2 },
  { path: '/user/history', label: 'History', icon: History },
  { path: '/user/profile', label: 'Profile', icon: CircleUserRound },
];

const UserSidebar = () => (
  <aside className="sidebar user-portal-sidebar">
    <div className="sidebar-header">
      <div className="sidebar-logo-icon">
        <Shield size={22} />
      </div>
      <div>
        <div className="sidebar-title">CYBER GUARD</div>
        <div className="sidebar-subtitle">Personal security portal</div>
      </div>
    </div>
    <nav className="sidebar-nav" aria-label="Normal User navigation">
      {navigation.map(({ path, label, icon: Icon }) => (
        <NavLink
          key={path}
          to={path}
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
        >
          <Icon size={18} aria-hidden="true" />
          <span>{label}</span>
        </NavLink>
      ))}
    </nav>
  </aside>
);

export default UserSidebar;
