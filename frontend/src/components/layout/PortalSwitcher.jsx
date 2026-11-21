import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { LayoutDashboard, Shield } from 'lucide-react';
import { getPortalOptions } from '../../utils/portalAccess';

const PORTAL_STATE_KEY = 'soc_selected_portal';

const PortalSwitcher = () => {
  const { user, loading } = useAuth();
  const location = useLocation();
  const role = user?.role;
  const portals = getPortalOptions(role, user?.permissions);

  if (loading || portals.length < 2) {
    return null;
  }

  const rememberPortal = (portal) => {
    window.sessionStorage.setItem(PORTAL_STATE_KEY, portal);
  };

  return (
    <nav className="portal-switcher" aria-label="Portal switcher">
      <span className="portal-switcher-caption">Workspace</span>
      {portals.map((portal) => {
        const isActive = portal.id === 'user'
          ? location.pathname.startsWith('/user/')
          : !location.pathname.startsWith('/user/');
        const Icon = portal.id === 'user' ? LayoutDashboard : Shield;
        return (
          <NavLink
            key={portal.id}
            to={portal.path}
            onClick={() => rememberPortal(portal.id)}
            className={`portal-switcher-option${isActive ? ' active' : ''}`}
            aria-current={isActive ? 'page' : undefined}
          >
            <Icon size={15} aria-hidden="true" />
            <span>{portal.label}</span>
          </NavLink>
        );
      })}
    </nav>
  );
};

export default PortalSwitcher;
