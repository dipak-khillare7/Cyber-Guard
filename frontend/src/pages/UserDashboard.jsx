import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, ArrowUpRight, Globe2, RefreshCw, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import ErrorState from '../components/common/ErrorState';
import LoadingState from '../components/common/LoadingState';
import UserRiskDistributionChart from '../components/user/UserRiskDistributionChart';
import WebsiteRiskBadge from '../components/user/WebsiteRiskBadge';
import { useAuth } from '../context/AuthContext';
import { websiteAssessmentService } from '../services/websiteAssessmentService';
import { formatDate } from '../utils/formatDate';

const EMPTY_DISTRIBUTION = {
  LOW: 0,
  MEDIUM: 0,
  HIGH: 0,
  CRITICAL: 0,
  INSUFFICIENT_INFORMATION: 0,
  ANALYSIS_UNAVAILABLE: 0,
};

const UserDashboard = () => {
  const { user } = useAuth();
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshVersion, setRefreshVersion] = useState(0);

  const refresh = useCallback(() => setRefreshVersion((value) => value + 1), []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    websiteAssessmentService.getSummary()
      .then((response) => {
        if (active) setSummary(response.data?.data || response.data);
      })
      .catch((requestError) => {
        if (active) setError(requestError.message || 'Could not load your website assessment summary.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [refreshVersion]);

  if (loading && !summary) {
    return <LoadingState message="Loading your website assessment activity…" />;
  }
  if (error && !summary) {
    return <ErrorState message={error} onRetry={refresh} />;
  }

  const distribution = { ...EMPTY_DISTRIBUTION, ...(summary?.risk_distribution || {}) };
  const recent = summary?.recent_assessments || [];
  const total = summary?.total_assessments || 0;

  return (
    <div className="user-portal-page">
      <header className="user-page-header">
        <div>
          <p className="user-eyebrow">YOUR WEBSITE SECURITY</p>
          <h1>Welcome, {user?.full_name || user?.username || 'there'}</h1>
          <p>Review website security analysis saved to your account.</p>
        </div>
        <div className="user-page-actions">
          <button className="btn btn-secondary" type="button" onClick={refresh} disabled={loading}>
            <RefreshCw size={16} aria-hidden="true" />
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
          <Link className="btn btn-primary" to="/user/check-website">
            <Search size={16} aria-hidden="true" /> Check a website
          </Link>
        </div>
      </header>

      {error && <p className="user-inline-error" role="status">{error}</p>}

      <section className="user-stat-grid" aria-label="Website assessment summary">
        <article className="user-stat-card">
          <span className="user-stat-icon blue"><Globe2 size={19} aria-hidden="true" /></span>
          <span className="user-stat-label">Total checks</span>
          <strong>{total}</strong>
          <span className="user-stat-note">Saved website security assessments</span>
        </article>
        <article className="user-stat-card">
          <span className="user-stat-icon green"><ShieldCheck size={19} aria-hidden="true" /></span>
          <span className="user-stat-label">Low risk indicator</span>
          <strong>{distribution.LOW}</strong>
          <span className="user-stat-note">No malicious or suspicious vendors reported</span>
        </article>
        <article className="user-stat-card">
          <span className="user-stat-icon amber"><Activity size={19} aria-hidden="true" /></span>
          <span className="user-stat-label">Medium risk indicator</span>
          <strong>{distribution.MEDIUM}</strong>
          <span className="user-stat-note">Provider or certificate warning evidence</span>
        </article>
        <article className="user-stat-card">
          <span className="user-stat-icon rose"><ShieldAlert size={19} aria-hidden="true" /></span>
          <span className="user-stat-label">High risk indicator</span>
          <strong>{distribution.HIGH}</strong>
          <span className="user-stat-note">At least one malicious vendor report</span>
        </article>
      </section>

      <div className="user-dashboard-grid">
        <UserRiskDistributionChart distribution={distribution} />
        <section className="user-portal-card user-recent-activity" aria-labelledby="recent-websites-title">
          <div className="user-card-heading">
            <div>
              <h2 id="recent-websites-title">Recent checks</h2>
              <p>Latest website reputation lookups associated with your account.</p>
            </div>
            <Link className="user-text-link" to="/user/history">
              View history <ArrowUpRight size={15} aria-hidden="true" />
            </Link>
          </div>
          {recent.length === 0 ? (
            <div className="user-empty-inline">
              <Globe2 size={22} aria-hidden="true" />
              <p>No website checks yet.</p>
              <Link to="/user/check-website">Check your first website</Link>
            </div>
          ) : (
            <div className="user-table-wrap">
              <table className="data-table user-activity-table">
                <caption className="sr-only">Your five most recent website assessments</caption>
                <thead>
                  <tr>
                    <th scope="col">Website</th>
                    <th scope="col">Checked</th>
                    <th scope="col">Provider result</th>
                    <th scope="col">Risk indicator</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((assessment) => (
                    <tr key={assessment.id}>
                      <td className="font-mono">{assessment.target_domain}</td>
                      <td>{formatDate(assessment.created_at)}</td>
                      <td>{assessment.provider_status.replaceAll('_', ' ')}</td>
                      <td><WebsiteRiskBadge level={assessment.risk_level} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      <p className="user-evidence-disclaimer">
        Reputation findings come from a third-party provider and are not proof that a site is safe or
        malicious. DNS and certificate analysis are not available in this version.
      </p>
    </div>
  );
};

export default UserDashboard;
