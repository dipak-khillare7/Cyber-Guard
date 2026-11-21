import React, { useEffect, useState } from 'react';
import { ArrowRight, Shield, ShieldAlert } from 'lucide-react';
import { accessRequestService } from '../../services/accessRequestService';

const AnalystAccessRequest = () => {
  const [accessRequest, setAccessRequest] = useState(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    accessRequestService.getMyAnalystRequest()
      .then((response) => {
        if (active) setAccessRequest(response.data?.data ?? response.data ?? null);
      })
      .catch((requestError) => {
        if (active) setError(requestError.message || 'Could not load Analyst access request status.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const submitRequest = async () => {
    if (submitting) return;
    setSubmitting(true);
    setError('');
    try {
      const response = await accessRequestService.requestAnalystAccess();
      setAccessRequest(response.data?.data ?? response.data);
    } catch (requestError) {
      setError(requestError.message || 'Could not submit the Analyst access request.');
    } finally {
      setSubmitting(false);
    }
  };

  const isPending = accessRequest?.status === 'PENDING';
  const isApproved = accessRequest?.status === 'APPROVED';
  const isRejected = accessRequest?.status === 'REJECTED';

  return (
    <section className="dashboard-select-card dashboard-select-analyst analyst-access-request">
      <span className="dashboard-select-icon"><Shield size={25} aria-hidden="true" /></span>
      <h2>SOC Analyst Dashboard</h2>
      <p>Investigate network security events and manage incidents. Analyst access requires administrator approval.</p>
      {error && <p className="analyst-access-error" role="alert">{error}</p>}
      {loading ? (
        <p role="status">Checking your Analyst access request…</p>
      ) : isPending ? (
        <p className="analyst-access-status" role="status">
          Your request is pending administrator approval.
        </p>
      ) : isApproved ? (
        <div className="analyst-access-status" role="status">
          <p>Your request was approved. Refresh your session to load the updated permissions.</p>
          <button className="dashboard-select-action" type="button" onClick={() => window.location.reload()}>
            Refresh permissions <ArrowRight size={17} aria-hidden="true" />
          </button>
        </div>
      ) : (
        <>
          {isRejected && (
            <p className="analyst-access-status" role="status">
              Your previous request was not approved. You may submit a new request.
            </p>
          )}
          {!isRejected && (
            <p className="analyst-access-status">
              <ShieldAlert size={16} aria-hidden="true" />
              This request does not change your account role or grant Analyst access.
            </p>
          )}
          <button
            className="dashboard-select-action"
            type="button"
            onClick={submitRequest}
            disabled={submitting}
          >
            {submitting ? 'Submitting request…' : 'Request Analyst access'}
            {!submitting && <ArrowRight size={17} aria-hidden="true" />}
          </button>
        </>
      )}
    </section>
  );
};

export default AnalystAccessRequest;
