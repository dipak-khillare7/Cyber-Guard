import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ArrowLeft, FileSearch } from 'lucide-react';
import ErrorState from '../components/common/ErrorState';
import LoadingState from '../components/common/LoadingState';
import UserResultDetails from '../components/user/UserResultDetails';
import { useUserActivity } from '../hooks/useUserActivity';

const MyResults = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { activity, loading, error, refresh } = useUserActivity();
  const analysis = location.state?.analysis || null;
  const selectedRecord = location.state?.record || null;
  const submittedEvent = location.state?.submission || null;
  const matchingRecord = analysis
    ? activity?.events.find((record) => record.event_id === analysis.event_id)
    : null;
  const record = selectedRecord || matchingRecord || (analysis
    ? {
      ...submittedEvent,
      event_id: analysis.event_id,
      alert_id: analysis.alert?.alert_id,
      detected_threat: analysis.prediction?.threat_type,
    }
    : activity?.events[0]);

  if (loading && !activity && !analysis && !selectedRecord) {
    return <LoadingState message="Loading your latest security result…" />;
  }

  if (error && !activity && !analysis && !selectedRecord) {
    return <ErrorState message={error} onRetry={refresh} />;
  }

  return (
    <div className="user-portal-page">
      <header className="user-page-header">
        <div>
          <p className="user-eyebrow">PERSONAL SECURITY ASSESSMENT</p>
          <h1>My results</h1>
          <p>Review the latest analysis associated with your account.</p>
        </div>
        <Link className="btn btn-secondary" to="/history">
          <ArrowLeft size={16} aria-hidden="true" />
          Back to history
        </Link>
      </header>

      {error && activity && (
        <p className="user-inline-error" role="status">
          Could not refresh your history. Showing the last loaded result. {error}
        </p>
      )}

      {record || analysis ? (
        <section className="user-portal-card user-result-page-card">
          <div className="user-card-heading">
            <div>
              <h2>{analysis ? `Analysis result · Event #${analysis.event_id}` : `Latest result · Event #${record.event_id}`}</h2>
              <p>
                {analysis
                  ? 'Values below come from the analysis response for the event you just submitted.'
                  : 'Historical detail is limited to information retained by the existing APIs.'}
              </p>
            </div>
            <FileSearch size={20} aria-hidden="true" />
          </div>
          <UserResultDetails record={record} analysis={analysis} />
        </section>
      ) : (
        <section className="user-portal-card user-empty-history">
          <FileSearch size={30} aria-hidden="true" />
          <h2>No security results yet</h2>
          <p>Submit a network event to receive an analysis tied to your account.</p>
          <button className="btn btn-primary" type="button" onClick={() => navigate('/submit-event')}>
            Submit an event
          </button>
        </section>
      )}
    </div>
  );
};

export default MyResults;
