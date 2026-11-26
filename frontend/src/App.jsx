import React from 'react';
import {
  BrowserRouter as Router,
  Navigate,
  Route,
  Routes,
} from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import ProtectedRoute from './components/common/ProtectedRoute';
import Sidebar from './components/layout/Sidebar';
import Topbar from './components/layout/Topbar';
import Login from './pages/Login';
import Register from './pages/Register';
import VerifyEmail from './pages/VerifyEmail';
import Dashboard from './pages/Dashboard';
import Analytics from './pages/Analytics';
import Detections from './pages/Detections';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import ResponseActions from './pages/ResponseActions';
import AuditLogs from './pages/AuditLogs';
import Settings from './pages/Settings';
import AnalystAccountRequests from './pages/AnalystAccountRequests';
import Unauthorized from './pages/Unauthorized';
import LoadingState from './components/common/LoadingState';
import { getAuthenticatedHome } from './utils/authRedirect';

const STAFF_ROLES = ['ANALYST', 'ADMIN'];

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
    return <LoadingState message="Checking your account permissions..." />;
  }
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Navigate to={getAuthenticatedHome(role)} replace />;
};

const LegacyStaffRoute = ({ analystPath, children }) => {
  const { role } = useAuth();
  return role === 'ANALYST' ? <Navigate to={analystPath} replace /> : children;
};

function AppLayout() {
  const { role } = useAuth();
  const hasStaffAccess = STAFF_ROLES.includes(role);

  return (
    <div
      className="app-container"
      style={{ display: 'flex', minHeight: '100vh', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)' }}
    >
      {hasStaffAccess && <Sidebar />}
      <div className="main-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {hasStaffAccess && <Topbar />}
        <main
          className="page-container"
          style={{ flex: 1, padding: '1.5rem 2rem', overflowY: 'auto' }}
        >
          <Routes>
            <Route path="/" element={<HomeRedirect />} />
            <Route
              path="/unauthorized"
              element={<ProtectedRoute><Unauthorized /></ProtectedRoute>}
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
              path="/analyst/analytics"
              element={<ProtectedRoute allowedRoles={STAFF_ROLES}><Analytics /></ProtectedRoute>}
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
              element={role === 'ANALYST'
                ? <Navigate to="/analyst/dashboard" replace />
                : <ProtectedRoute allowedRoles={['ADMIN']}><Dashboard /></ProtectedRoute>}
            />
            <Route
              path="/admin/analyst-requests"
              element={<ProtectedRoute allowedRoles={['ADMIN']}><AnalystAccountRequests /></ProtectedRoute>}
            />
            <Route
              path="/detections"
              element={
                <ProtectedRoute allowedRoles={STAFF_ROLES}>
                  <LegacyStaffRoute analystPath="/analyst/detections"><Detections /></LegacyStaffRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/analytics"
              element={
                <ProtectedRoute allowedRoles={STAFF_ROLES}>
                  <LegacyStaffRoute analystPath="/analyst/analytics"><Analytics /></LegacyStaffRoute>
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
