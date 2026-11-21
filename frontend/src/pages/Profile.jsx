import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { BadgeCheck, CalendarDays, KeyRound, LogOut, Mail, UserRound } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { formatDate } from '../utils/formatDate';

const Profile = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [loggingOut, setLoggingOut] = useState(false);

  const handleLogout = async () => {
    if (loggingOut) return;
    setLoggingOut(true);
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="user-portal-page">
      <header className="user-page-header">
        <div>
          <p className="user-eyebrow">ACCOUNT</p>
          <h1>Profile</h1>
          <p>Review the account currently used to submit and view security events.</p>
        </div>
      </header>

      <section className="user-portal-card user-profile-card" aria-labelledby="profile-details-title">
        <div className="user-profile-heading">
          <span className="user-profile-avatar" aria-hidden="true">
            <UserRound size={25} />
          </span>
          <div>
            <h2 id="profile-details-title">{user?.full_name || user?.username || 'Normal User'}</h2>
            <span className="user-profile-role">
              {user?.role === 'ADMIN' ? 'Administrator' : user?.role === 'ANALYST' ? 'SOC Analyst' : 'Normal User'}
            </span>
          </div>
        </div>
        <dl className="user-profile-details">
          <div>
            <dt><UserRound size={16} aria-hidden="true" /> Username</dt>
            <dd>{user?.username || 'Not available'}</dd>
          </div>
          <div>
            <dt><Mail size={16} aria-hidden="true" /> Email</dt>
            <dd>{user?.email || 'Not available'}</dd>
          </div>
          <div>
            <dt><BadgeCheck size={16} aria-hidden="true" /> Email verification</dt>
            <dd>{user?.email_verified ? 'Verified' : 'Not verified'}</dd>
          </div>
          <div>
            <dt><CalendarDays size={16} aria-hidden="true" /> Account created</dt>
            <dd>{user?.created_at ? formatDate(user.created_at) : 'Not available'}</dd>
          </div>
        </dl>
        <div className="user-profile-notice">
          <KeyRound size={18} aria-hidden="true" />
          <p>
            Account details are read-only in this portal. Contact a platform administrator for account
            changes; password changes are not exposed by the current API.
          </p>
        </div>
        <div className="user-profile-actions">
          <button
            className="btn btn-danger"
            type="button"
            onClick={handleLogout}
            disabled={loggingOut}
          >
            <LogOut size={16} aria-hidden="true" />
            {loggingOut ? 'Signing out…' : 'Log out securely'}
          </button>
        </div>
      </section>
    </div>
  );
};

export default Profile;
