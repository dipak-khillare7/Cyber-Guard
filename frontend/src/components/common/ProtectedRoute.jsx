import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import LoadingState from './LoadingState';
import { getPortalHome } from '../../utils/portalAccess';

const ProtectedRoute = ({ children, allowedRoles = [] }) => {
  const { isAuthenticated, user, loading, hasRole } = useAuth();
  const location = useLocation();
  const roleHome = getPortalHome(user?.role);

  if (loading) {
    return <LoadingState message="Verifying session credentials & role permissions..." />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles.length > 0 && !hasRole(allowedRoles)) {
    return (
      <Navigate
        to="/unauthorized"
        replace
        state={{
          role: user?.role || 'GUEST',
          attemptedPath: location.pathname,
        }}
      />
    );
  }

  return children;
};

export default ProtectedRoute;
