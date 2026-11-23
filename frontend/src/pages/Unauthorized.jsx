import React from 'react';
import { ShieldAlert } from 'lucide-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { getAuthenticatedHome } from '../utils/authRedirect';

const Unauthorized = () => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const attemptedPath = location.state?.attemptedPath;
  const home = getAuthenticatedHome(user?.role);

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <main className="unauthorized-page" role="alert">
      <span className="unauthorized-icon"><ShieldAlert size={28} aria-hidden="true" /></span>
      <h1>Access denied</h1>
      <p>
        Your account is not authorized to access this resource. Contact an administrator if you need SOC access.
        {attemptedPath ? ` Attempted route: ${attemptedPath}` : ''}
      </p>
      {home !== '/unauthorized' ? (
        <Link className="btn btn-primary" to={home}>Return to your SOC workspace</Link>
      ) : (
        <button className="btn btn-primary" type="button" onClick={handleLogout}>Sign out</button>
      )}
    </main>
  );
};

export default Unauthorized;
