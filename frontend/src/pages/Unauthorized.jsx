import React from 'react';
import { ShieldAlert } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { getPortalHome } from '../utils/portalAccess';
import AnalystAccessRequest from '../components/common/AnalystAccessRequest';

const Unauthorized = () => {
  const { user } = useAuth();
  const location = useLocation();
  const attemptedPath = location.state?.attemptedPath;
  const home = getPortalHome(user?.role);

  return (
    <main className="unauthorized-page" role="alert">
      <span className="unauthorized-icon"><ShieldAlert size={28} aria-hidden="true" /></span>
      <h1>Access denied</h1>
      <p>
        Your account is not authorized to open this workspace or resource.
        {attemptedPath ? ` Attempted route: ${attemptedPath}` : ''}
      </p>
      <Link className="btn btn-primary" to={home}>Return to my authorized workspace</Link>
      {user?.role === 'VIEWER' && <AnalystAccessRequest />}
    </main>
  );
};

export default Unauthorized;
