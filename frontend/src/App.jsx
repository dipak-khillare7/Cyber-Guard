import React, { useEffect } from 'react';
import {
  BrowserRouter as Router,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import ProtectedRoute from './components/common/ProtectedRoute';
import Sidebar from './components/layout/Sidebar';
import Topbar from './components/layout/Topbar';
import UserSidebar from './components/user/UserSidebar';
import UserTopbar from './components/user/UserTopbar';
import Login from './pages/Login';
import Register from './pages/Register';
import VerifyEmail from './pages/VerifyEmail';
import Dashboard from './pages/Dashboard';
import UserDashboard from './pages/UserDashboard';
import Detections from './pages/Detections';
import WebsiteCheck from './pages/WebsiteCheck';
import WebsiteHistory from './pages/WebsiteHistory';
import Profile from './pages/Profile';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import ResponseActions from './pages/ResponseActions';
import AuditLogs from './pages/AuditLogs';
import Settings from './pages/Settings';
import DashboardSelect from './pages/DashboardSelect';
import Unauthorized from './pages/Unauthorized';
import AnalystAccessRequests from './pages/AnalystAccessRequests';
import LoadingState from './components/common/LoadingState';
import {
  getPortalHome,
  STAFF_PORTAL_ROLES as STAFF_ROLES,
  USER_PORTAL_ROLES as USER_ROLES,
} from './utils/portalAccess';
const PORTAL_STATE_KEY = 'soc_selected_portal';

class AppErrorBoundary extends React.Component {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Application render error:', error, errorInfo);
  }

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return (
      <main className="app-render-error" role="alert">
        <section className="app-render-error-card">
          <h1>We couldn’t load this page</h1>
          <p>An unexpected application error occurred. Reload the page to try again.</p>
          <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
            Reload page
          </button>
        </section>
      </main>
    );
  }
}

const HomeRedirect = () => {
  const { role, isAuthenticated, loading } = useAuth();

  if (loading) {
    return <LoadingState message="Validating your account and portal access..." />;
  }
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  const savedPortal = window.sessionStorage.getItem(PORTAL_STATE_KEY);
  return <Navigate to={getPortalHome(role, savedPortal)} replace />;
};

const LegacyStaffRoute = ({ analystPath, children }) => {
  const { role } = useAuth();
  return role === 'ANALYST' ? <Navigate to={analystPath} replace /> : children;
};

function AppLayout() {
  const { role, loading } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const isWorkspaceSelection = location.pathname === '/dashboard/select';
  const isUserPortal = location.pathname.startsWith('/user/') || role === 'VIEWER';

  useEffect(() => {
    if (loading) return;
    if (location.pathname === '/dashboard/select' || location.pathname === '/unauthorized') return;
    const activePortal = isUserPortal ? 'user' : 'analyst';
    window.sessionStorage.setItem(PORTAL_STATE_KEY, activePortal);
  }, [isUserPortal, loading, location.pathname]);

  const dismissAccessDenied = () => {
    navigate(location.pathname, { replace: true, state: null });
  };

  return (
    <div
      className={`app-container${isUserPortal ? ' user-portal-shell' : ''}`}
      style={{ display: 'flex', minHeight: '100vh', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)' }}
    >
      {!isWorkspaceSelection && (isUserPortal ? <UserSidebar /> : <Sidebar />)}
      <div className="main-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {!isWorkspaceSelection && (isUserPortal ? <UserTopbar /> : <Topbar />)}
        <main
          className={isWorkspaceSelection ? 'workspace-selection-container' : 'page-container'}
          style={{ flex: 1, padding: '1.5rem 2rem', overflowY: 'auto' }}
        >
          {location.state?.accessDenied && (
            <div className="portal-access-denied" role="alert">
              <span>
                Access denied: your {location.state.accessDenied.role} account cannot open that portal page.
                You were redirected to an authorized portal.
              </span>
              <button type="button" onClick={dismissAccessDenied} aria-label="Dismiss access denied message">
                Dismiss
              </button>
            </div>
          )}
          <Routes>
            <Route path="/" element={<HomeRedirect />} />
            <Route
              path="/dashboard/select"
              element={<ProtectedRoute allowedRoles={USER_ROLES}><DashboardSelect /></ProtectedRoute>}
            />
            <Route
              path="/unauthorized"
              element={<ProtectedRoute allowedRoles={USER_ROLES}><Unauthorized /></ProtectedRoute>}
            />
            <Route
              path="/admin/access-requests"
              element={<ProtectedRoute allowedRoles={['ADMIN']}><AnalystAccessRequests /></ProtectedRoute>}
            />
            <Route path="/user" element={<Navigate to="/user/dashboard" replace />} />
            <Route
              path="/user/dashboard"
              element={<ProtectedRoute allowedRoles={USER_ROLES}><UserDashboard /></ProtectedRoute>}
            />
            <Route
              path="/user/check-website"
              element={<ProtectedRoute allowedRoles={USER_ROLES}><WebsiteCheck /></ProtectedRoute>}
            />
            <Route
              path="/user/submit-event"
              element={<Navigate to="/user/check-website" replace />}
            />
            <Route
              path="/user/results"
              element={<ProtectedRoute allowedRoles={USER_ROLES}><WebsiteHistory /></ProtectedRoute>}
            />
            <Route
              path="/user/history"
              element={<ProtectedRoute allowedRoles={USER_ROLES}><WebsiteHistory /></ProtectedRoute>}
            />
            <Route
              path="/user/profile"
              element={<ProtectedRoute allowedRoles={USER_ROLES}><Profile /></ProtectedRoute>}
            />

            <Route path="/analyst" element={<Navigate to="/analyst/dashboard" replace />} />
            <Route
              path="/analyst/dashboard"
              element={<ProtectedRoute allowedRoles={STAFF_ROLES}><Dashboard /></ProtectedRoute>}
            />
            <Route
              path="/analyst/detections"
              element={<ProtectedRoute allowedRoles={STAFF_ROLES}><Detections /></ProtectedRoute>}
            />
            <Route
              path="/analyst/investigations"
              element={<ProtectedRoute allowedRoles={STAFF_ROLES}><Detections /></ProtectedRoute>}
            />
            <Route
              path="/analyst/alerts"
              element={<ProtectedRoute allowedRoles={STAFF_ROLES}><Alerts /></ProtectedRoute>}
            />
            <Route
              path="/analyst/incidents"
              element={<ProtectedRoute allowedRoles={STAFF_ROLES}><Incidents /></ProtectedRoute>}
            />
            <Route
              path="/analyst/response-actions"
              element={<ProtectedRoute allowedRoles={STAFF_ROLES}><ResponseActions /></ProtectedRoute>}
            />
            <Route
              path="/analyst/audit-logs"
              element={<ProtectedRoute allowedRoles={STAFF_ROLES}><AuditLogs /></ProtectedRoute>}
            />
            <Route
              path="/analyst/settings"
              element={<ProtectedRoute allowedRoles={STAFF_ROLES}><Settings /></ProtectedRoute>}
            />

            <Route
              path="/dashboard"
              element={
                role === 'VIEWER'
                  ? <Navigate to="/user/dashboard" replace />
                  : role === 'ANALYST'
                    ? <Navigate to="/analyst/dashboard" replace />
                    : <ProtectedRoute allowedRoles={STAFF_ROLES}><Dashboard /></ProtectedRoute>
              }
            />
            <Route
              path="/submit-event"
              element={<Navigate to="/user/check-website" replace />}
            />
            <Route path="/my-results" element={<Navigate to="/user/results" replace />} />
            <Route path="/history" element={<Navigate to="/user/history" replace />} />
            <Route path="/profile" element={<Navigate to="/user/profile" replace />} />
            <Route
              path="/detections"
              element={
                <ProtectedRoute allowedRoles={STAFF_ROLES}>
                  <LegacyStaffRoute analystPath="/analyst/detections"><Detections /></LegacyStaffRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/alerts"
              element={
                <ProtectedRoute allowedRoles={STAFF_ROLES}>
                  <LegacyStaffRoute analystPath="/analyst/alerts"><Alerts /></LegacyStaffRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/incidents"
              element={
                <ProtectedRoute allowedRoles={STAFF_ROLES}>
                  <LegacyStaffRoute analystPath="/analyst/incidents"><Incidents /></LegacyStaffRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/response-actions"
              element={
                <ProtectedRoute allowedRoles={STAFF_ROLES}>
                  <LegacyStaffRoute analystPath="/analyst/response-actions"><ResponseActions /></LegacyStaffRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/audit-logs"
              element={
                <ProtectedRoute allowedRoles={STAFF_ROLES}>
                  <LegacyStaffRoute analystPath="/analyst/audit-logs"><AuditLogs /></LegacyStaffRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/settings"
              element={
                <ProtectedRoute allowedRoles={STAFF_ROLES}>
                  <LegacyStaffRoute analystPath="/analyst/settings"><Settings /></LegacyStaffRoute>
                </ProtectedRoute>
              }
            />
            <Route path="*" element={<HomeRedirect />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

function App() {
  return (
    <AppErrorBoundary>
      <AuthProvider>
        <Router>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/verify-email" element={<VerifyEmail />} />
            <Route path="/*" element={<AppLayout />} />
          </Routes>
        </Router>
      </AuthProvider>
    </AppErrorBoundary>
  );
}

export default App;
