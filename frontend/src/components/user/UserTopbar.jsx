import React, { useState } from 'react';
import { LogOut, ShieldCheck } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import PortalSwitcher from '../layout/PortalSwitcher';

const UserTopbar = () => {
  const { user, logout } = useAuth();
  const [loggingOut, setLoggingOut] = useState(false);

  const handleLogout = async () => {
    if (loggingOut) return;
    setLoggingOut(true);
    await logout();
  };

  return (
    <header className="navbar user-portal-topbar">
      <div className="user-topbar-brand">
        <ShieldCheck size={22} aria-hidden="true" />
        <div>
          <strong>Personal Security Portal</strong>
          <span>Check websites and review reputation results</span>
        </div>
      </div>
      <div className="user-topbar-account">
        <PortalSwitcher />
        <div>
          <strong>{user?.full_name || user?.username || 'Account'}</strong>
          <span>Personal security view</span>
        </div>
        <button
          className="btn btn-secondary"
          type="button"
          onClick={handleLogout}
          disabled={loggingOut}
          aria-label="Log out of your account"
        >
          <LogOut size={15} aria-hidden="true" />
          {loggingOut ? 'Signing out…' : 'Log out'}
        </button>
      </div>
    </header>
  );
};

export default UserTopbar;
