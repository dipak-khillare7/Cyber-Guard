import React, { useRef, useState } from 'react';
import { AlertCircle, Globe2, Loader2, Search, ShieldCheck } from 'lucide-react';
import { websiteAssessmentService } from '../services/websiteAssessmentService';
import { validateWebsiteUrl } from '../utils/websiteUrl';
import WebsiteAssessmentDetails from '../components/user/WebsiteAssessmentDetails';

const createIdempotencyKey = () => {
  if (window.crypto.randomUUID) return window.crypto.randomUUID();
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
};

const WebsiteCheck = () => {
  const [url, setUrl] = useState('');
  const [consent, setConsent] = useState(false);
  const [assessment, setAssessment] = useState(null);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const submitLock = useRef(false);
  const idempotencyKey = useRef(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (submitLock.current) return;

    const validationMessage = validateWebsiteUrl(url);
    if (validationMessage) {
      setError(validationMessage);
      setAssessment(null);
      return;
    }
    if (!consent) {
      setError('Consent is required before running DNS/TLS checks and sharing the URL with VirusTotal.');
      setAssessment(null);
      return;
    }

    submitLock.current = true;
    setSubmitting(true);
    setError('');
    setAssessment(null);
    try {
      idempotencyKey.current ||= createIdempotencyKey();
      const response = await websiteAssessmentService.create(
        url,
        consent,
        idempotencyKey.current,
      );
      setAssessment(response.data?.data || response.data);
      idempotencyKey.current = null;
    } catch (requestError) {
      setError(requestError.message || 'The website could not be checked. Please try again later.');
    } finally {
      submitLock.current = false;
      setSubmitting(false);
    }
  };

  return (
    <div className="user-portal-page">
      <header className="user-page-header">
        <div>
          <p className="user-eyebrow">WEBSITE SECURITY CHECK</p>
          <h1>Check a website</h1>
          <p>Review DNS, certificate, and available third-party reputation evidence before browsing.</p>
        </div>
      </header>

      <section className="user-portal-card website-check-card">
        <div className="website-check-intro">
          <span className="user-stat-icon blue"><Globe2 size={20} aria-hidden="true" /></span>
          <div>
            <h2>Enter a website URL</h2>
            <p>Only HTTP and HTTPS URLs for public websites are supported.</p>
          </div>
        </div>
        {error && (
          <div className="user-form-alert error" role="alert">
            <AlertCircle size={18} aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}
        <form className="website-check-form" onSubmit={handleSubmit} noValidate>
          <label htmlFor="website-url">Website URL</label>
          <div className="website-url-entry">
            <input
              id="website-url"
              name="url"
              type="url"
              autoComplete="url"
              inputMode="url"
              placeholder="https://example.com"
              value={url}
              onChange={(event) => {
                setUrl(event.target.value);
                setError('');
                idempotencyKey.current = null;
              }}
              aria-describedby="website-url-help"
              required
              disabled={submitting}
            />
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting
                ? <><Loader2 size={16} className="animate-spin" aria-hidden="true" /> Checking…</>
                : <><Search size={16} aria-hidden="true" /> Check website</>}
            </button>
          </div>
          <small id="website-url-help">Include the full address, such as https://example.com.</small>

          <label className="website-consent">
            <input
              type="checkbox"
              checked={consent}
              onChange={(event) => {
                setConsent(event.target.checked);
                setError('');
              }}
              disabled={submitting}
              required
            />
            <span>
              I consent to public DNS record lookups and one standard HTTPS certificate check, and to sharing
              this exact URL with VirusTotal for a reputation report. The URL, including its path and query
              string (but not its fragment), may be added to VirusTotal’s shared dataset. I will not submit
              private, personal, or confidential URLs.
            </span>
          </label>
          <p className="website-passive-note">
            <ShieldCheck size={16} aria-hidden="true" />
            This check queries DNS and may perform one TLS handshake on port 443. It does not fetch website
            content, follow redirects, scan ports, or perform vulnerability scanning.
          </p>
        </form>
      </section>

      {assessment && (
        <section className="user-portal-card" aria-live="polite">
          <WebsiteAssessmentDetails assessment={assessment} />
        </section>
      )}
    </div>
  );
};

export default WebsiteCheck;
