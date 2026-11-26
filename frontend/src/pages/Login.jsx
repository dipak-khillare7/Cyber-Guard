import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { AlertCircle, CheckCircle2, Eye, EyeOff, LockKeyhole, Mail, Shield } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { authService } from '../services/authService';
import { getAuthenticatedHome } from '../utils/authRedirect';
import '../styles/auth.css';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [needsVerification, setNeedsVerification] = useState(false);
  const [resendMessage, setResendMessage] = useState('');
  const [resending, setResending] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const verified = location.state?.verified;
  const sessionExpired = new URLSearchParams(location.search).get('expired') === 'true';

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setResendMessage('');
    setNeedsVerification(false);
    setSubmitting(true);
    try {
      const result = await login(email.trim(), password);
      navigate(getAuthenticatedHome(result.user?.role), { replace: true });
    } catch (requestError) {
      const message = requestError.message || 'Unable to sign in. Check your credentials and try again.';
      setError(message);
      setNeedsVerification(message.toLowerCase().includes('email verification is required'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleResend = async () => {
    setResending(true);
    setResendMessage('');
    try {
      const result = await authService.resendVerification(email.trim());
      setResendMessage(result.message);
    } catch (requestError) {
      setResendMessage(requestError.message || 'Unable to resend the verification email.');
    } finally {
      setResending(false);
    }
  };

  return (
    <main className="auth-page">
      <section className="auth-card" aria-labelledby="login-title">
        <div className="auth-brand">
          <div className="auth-brand-icon"><Shield size={25} /></div>
          <span>CYBER GUARD</span>
          <small>SOC MONITORING CONSOLE</small>
        </div>
        <div className="auth-heading">
          <p className="auth-eyebrow">SECURE ACCESS</p>
          <h1 id="login-title">Welcome back</h1>
          <p>Sign in to continue to your security operations workspace.</p>
        </div>

        {verified && (
          <div className="auth-notice auth-notice-success" role="status">
            <CheckCircle2 size={18} />
            <span>{location.state?.verifiedMessage || 'Your email has been verified successfully.'}</span>
          </div>
        )}
        {sessionExpired && !error && (
          <div className="auth-notice auth-notice-error" role="alert">
            <AlertCircle size={18} />
            <span>Your session expired. Please sign in again to continue.</span>
          </div>
        )}
        {error && (
          <div className="auth-notice auth-notice-error" role="alert">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        <form className="auth-form" onSubmit={handleSubmit}>
          <label className="auth-field">
            <span>Email Address</span>
            <span className="auth-input-wrap">
              <Mail size={17} aria-hidden="true" />
              <input
                type="text"
                name="email"
                autoComplete="username"
                placeholder="you@example.com"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
            </span>
          </label>
          <label className="auth-field">
            <span>Password</span>
            <span className="auth-input-wrap">
              <LockKeyhole size={17} aria-hidden="true" />
              <input
                type={showPassword ? 'text' : 'password'}
                name="password"
                autoComplete="current-password"
                placeholder="Enter your password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
              <button
                className="auth-visibility-button"
                type="button"
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                onClick={() => setShowPassword((current) => !current)}
              >
                {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </span>
          </label>
          <button className="auth-submit" type="submit" disabled={submitting}>
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        {needsVerification && (
          <div className="auth-resend">
            <p>Verify your email address to access your account.</p>
            <Link
              className="auth-text-button"
              to="/verify-email"
              state={{ email }}
            >
              Enter verification code
            </Link>
            <p>Or request a new code:</p>
            <button type="button" className="auth-text-button" onClick={handleResend} disabled={resending || !email}>
              {resending ? 'Sending…' : 'Resend verification code'}
            </button>
            {resendMessage && <p className="auth-inline-message" role="status">{resendMessage}</p>}
          </div>
        )}

        <div className="auth-footer">
          <span>Don’t have an account?</span>
          <Link to="/register">Create Account</Link>
          <p>Admins may also sign in with their existing username.</p>
        </div>
      </section>
    </main>
  );
};

export default Login;
