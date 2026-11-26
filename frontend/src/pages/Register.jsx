import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AlertCircle, Eye, EyeOff, LockKeyhole, Mail, UserRound, Shield } from 'lucide-react';
import { authService } from '../services/authService';
import '../styles/auth.css';

const Register = () => {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    if (password !== confirmPassword) {
      setError('Password and confirmation do not match.');
      return;
    }
    setSubmitting(true);
    try {
      const result = await authService.register({
        full_name: fullName.trim(),
        email: email.trim(),
        password,
        confirm_password: confirmPassword,
      });
      navigate('/verify-email', { state: { email: email.trim(), message: result.message } });
    } catch (requestError) {
      setError(requestError.message || 'Unable to create your account. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-page">
      <section className="auth-card auth-card-register" aria-labelledby="register-title">
        <div className="auth-brand">
          <div className="auth-brand-icon"><Shield size={25} /></div>
          <span>CYBER GUARD</span>
          <small>SOC MONITORING CONSOLE</small>
        </div>
        <div className="auth-heading">
          <p className="auth-eyebrow">SOC ANALYST REGISTRATION</p>
          <h1 id="register-title">Request an analyst account</h1>
          <p>Verify your email, then wait for an Admin to review your request.</p>
        </div>

        {error && (
          <div className="auth-notice auth-notice-error" role="alert">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}
        <form className="auth-form" onSubmit={handleSubmit}>
          <label className="auth-field">
            <span>Full Name</span>
            <span className="auth-input-wrap">
              <UserRound size={17} aria-hidden="true" />
              <input
                type="text"
                name="full_name"
                autoComplete="name"
                placeholder="Your full name"
                value={fullName}
                onChange={(event) => setFullName(event.target.value)}
                minLength={2}
                maxLength={150}
                required
              />
            </span>
          </label>
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
            <span>Password</span>
            <span className="auth-input-wrap">
              <LockKeyhole size={17} aria-hidden="true" />
              <input
                type={showPassword ? 'text' : 'password'}
                name="password"
                autoComplete="new-password"
                placeholder="Create a strong password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                minLength={12}
                maxLength={72}
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
            <small className="auth-hint">At least 12 characters with upper/lowercase, a number, and a symbol.</small>
          </label>
          <label className="auth-field">
            <span>Confirm Password</span>
            <span className="auth-input-wrap">
              <LockKeyhole size={17} aria-hidden="true" />
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                name="confirm_password"
                autoComplete="new-password"
                placeholder="Enter your password again"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                minLength={12}
                maxLength={72}
                required
              />
              <button
                className="auth-visibility-button"
                type="button"
                aria-label={showConfirmPassword ? 'Hide confirmation password' : 'Show confirmation password'}
                onClick={() => setShowConfirmPassword((current) => !current)}
              >
                {showConfirmPassword ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </span>
          </label>
          <button className="auth-submit" type="submit" disabled={submitting}>
            {submitting ? 'Creating account…' : 'Create Account'}
          </button>
        </form>

        <div className="auth-footer">
          <span>Already have an account?</span>
          <Link to="/login">Login</Link>
        </div>
      </section>
    </main>
  );
};

export default Register;
