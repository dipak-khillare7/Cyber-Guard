import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { AlertCircle, CheckCircle2, Loader2, Mail, Shield } from 'lucide-react';
import { authService } from '../services/authService';
import '../styles/auth.css';

const VerifyEmail = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [email, setEmail] = useState(location.state?.email || '');
  const [otp, setOtp] = useState('');
  const [status, setStatus] = useState('idle');
  const [submitting, setSubmitting] = useState(false);
  const [resending, setResending] = useState(false);
  const [message, setMessage] = useState(location.state?.message || '');
  const [error, setError] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    setMessage('');
    try {
      const result = await authService.verifyEmail(email.trim(), otp);
      setStatus('success');
      setMessage(result.message);
      window.setTimeout(
        () => navigate('/login', { replace: true, state: { verified: true } }),
        1800,
      );
    } catch (requestError) {
      setStatus('idle');
      setError(requestError.message || 'The verification code is invalid or has expired.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleResend = async () => {
    if (!email.trim()) {
      setError('Enter your email address to request a new code.');
      return;
    }
    setResending(true);
    setError('');
    setMessage('');
    try {
      const result = await authService.resendVerification(email.trim());
      setMessage(result.message);
    } catch (requestError) {
      setError(requestError.message || 'Unable to resend the verification code.');
    } finally {
      setResending(false);
    }
  };

  return (
    <main className="auth-page">
      <section className="auth-card auth-card-verify" aria-labelledby="verify-title">
        <div className="auth-brand">
          <div className="auth-brand-icon"><Shield size={25} /></div>
          <span>CYBER GUARD</span>
          <small>SOC MONITORING CONSOLE</small>
        </div>

        {status === 'success' ? (
          <div className="auth-state" role="status">
            <CheckCircle2 className="auth-state-icon success" size={42} />
            <h1 id="verify-title">Email verified</h1>
            <p className="auth-success-copy">Your email has been verified successfully. You can now log in.</p>
            <p>Redirecting you to login…</p>
          </div>
        ) : (
          <>
            <div className="auth-heading">
              <p className="auth-eyebrow">EMAIL VERIFICATION</p>
              <h1 id="verify-title">Enter your code</h1>
              <p>We sent a 6-digit code to your email. The code expires in 10 minutes.</p>
            </div>

            {error && (
              <div className="auth-notice auth-notice-error" role="alert">
                <AlertCircle size={18} />
                <span>{error}</span>
              </div>
            )}
            {message && (
              <div className="auth-notice auth-notice-success" role="status">
                <Mail size={18} />
                <span>{message}</span>
              </div>
            )}

            <form className="auth-form" onSubmit={handleSubmit}>
              <label className="auth-field">
                <span>Email Address</span>
                <span className="auth-input-wrap">
                  <Mail size={17} aria-hidden="true" />
                  <input
                    type="email"
                    name="email"
                    autoComplete="email"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    required
                  />
                </span>
              </label>
              <label className="auth-field">
                <span>6-digit verification code</span>
                <input
                  className="auth-otp-input"
                  type="text"
                  name="otp"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  placeholder="000000"
                  value={otp}
                  onChange={(event) => setOtp(event.target.value.replace(/\D/g, '').slice(0, 6))}
                  required
                />
              </label>
              <button className="auth-submit" type="submit" disabled={submitting || otp.length !== 6}>
                {submitting ? <><Loader2 className="auth-inline-spinner" size={16} /> Verifying…</> : 'Verify email'}
              </button>
            </form>

            <div className="auth-resend">
              <p>Didn’t receive the code?</p>
              <button type="button" className="auth-text-button" onClick={handleResend} disabled={resending}>
                {resending ? 'Sending…' : 'Resend verification code'}
              </button>
            </div>

            <div className="auth-footer">
              <span>Already verified?</span>
              <Link to="/login">Login</Link>
            </div>
          </>
        )}
      </section>
    </main>
  );
};

export default VerifyEmail;
