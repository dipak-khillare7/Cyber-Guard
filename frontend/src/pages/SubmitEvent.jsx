import React, { useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AlertCircle, ArrowRight, CheckCircle2, RefreshCw, Send } from 'lucide-react';
import { detectionService } from '../services/detectionService';
import { useUserActivity } from '../hooks/useUserActivity';
import { isValidIpAddress } from '../utils/userPortal';
import UserResultDetails from '../components/user/UserResultDetails';

const emptyForm = {
  source_ip: '',
  destination_ip: '',
  source_port: '',
  destination_port: '',
  protocol: '',
  duration: '',
  packet_count: '',
  byte_count: '',
  syn_flag_count: '',
  ack_flag_count: '',
};

const EventField = ({ id, label, help, error, ...inputProps }) => (
  <div className="user-form-field">
    <label htmlFor={id}>{label}</label>
    <input
      id={id}
      name={id}
      aria-invalid={Boolean(error)}
      aria-describedby={`${id}-help${error ? ` ${id}-error` : ''}`}
      {...inputProps}
    />
    <small id={`${id}-help`}>{help}</small>
    {error && <span className="user-field-error" id={`${id}-error`}>{error}</span>}
  </div>
);

const SubmitEvent = () => {
  const navigate = useNavigate();
  const { refresh } = useUserActivity();
  const [formData, setFormData] = useState(emptyForm);
  const [analysis, setAnalysis] = useState(null);
  const [submittedEvent, setSubmittedEvent] = useState(null);
  const [fieldErrors, setFieldErrors] = useState({});
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const submitLock = useRef(false);

  const updateField = (event) => {
    const { name, value } = event.target;
    setFormData((current) => ({ ...current, [name]: value }));
    setFieldErrors((current) => ({ ...current, [name]: '' }));
    setError('');
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (submitLock.current) return;

    const validationErrors = {};
    if (!isValidIpAddress(formData.source_ip)) {
      validationErrors.source_ip = 'Enter a valid IPv4 or IPv6 address.';
    }
    if (!isValidIpAddress(formData.destination_ip)) {
      validationErrors.destination_ip = 'Enter a valid IPv4 or IPv6 address.';
    }
    if (Object.keys(validationErrors).length > 0) {
      setFieldErrors(validationErrors);
      return;
    }

    const payload = {
      source_ip: formData.source_ip.trim(),
      destination_ip: formData.destination_ip.trim(),
      source_port: Number(formData.source_port),
      destination_port: Number(formData.destination_port),
      protocol: formData.protocol,
      duration: Number(formData.duration),
      packet_count: Number(formData.packet_count),
      byte_count: Number(formData.byte_count),
      event_type: 'NETWORK',
    };
    if (formData.syn_flag_count !== '') payload.syn_flag_count = Number(formData.syn_flag_count);
    if (formData.ack_flag_count !== '') payload.ack_flag_count = Number(formData.ack_flag_count);

    submitLock.current = true;
    setSubmitting(true);
    setError('');
    setAnalysis(null);
    setSubmittedEvent(null);

    try {
      const response = await detectionService.analyzeEvent(payload);
      const result = response.data?.data || response.data;
      if (!result?.event_id || !result?.prediction || !result?.risk) {
        throw new Error('The analysis service returned an incomplete result. Please try again later.');
      }
      setAnalysis(result);
      setSubmittedEvent(payload);
      refresh();
    } catch (requestError) {
      setError(requestError.message || 'The event could not be analyzed. Please try again.');
    } finally {
      submitLock.current = false;
      setSubmitting(false);
    }
  };

  const startAnother = () => {
    setFormData(emptyForm);
    setAnalysis(null);
    setSubmittedEvent(null);
    setFieldErrors({});
    setError('');
  };

  return (
    <div className="user-portal-page">
      <header className="user-page-header">
        <div>
          <p className="user-eyebrow">SECURITY ASSESSMENT</p>
          <h1>Submit a network event</h1>
          <p>Enter flow details from a source you are authorized to review. This does not scan or contact either address.</p>
        </div>
        <Link className="btn btn-secondary" to="/history">View my history</Link>
      </header>

      <section className="user-portal-card user-form-card">
        {analysis ? (
          <div className="user-submission-success" role="status" aria-live="polite">
            <div className="user-success-heading">
              <CheckCircle2 size={22} aria-hidden="true" />
              <div>
                <h2>Event submitted and analyzed</h2>
                <p>Event #{analysis.event_id} was saved to your account.</p>
              </div>
            </div>
            <UserResultDetails
              record={{ ...submittedEvent, event_id: analysis.event_id, alert_id: analysis.alert?.alert_id, detected_threat: analysis.prediction?.threat_type }}
              analysis={analysis}
            />
            <div className="user-form-actions">
              <button
                className="btn btn-secondary"
                type="button"
                onClick={startAnother}
              >
                Submit another event
              </button>
              <button
                className="btn btn-primary"
                type="button"
                onClick={() => navigate('/my-results', {
                  state: { analysis, submission: submittedEvent },
                })}
              >
                View this result <ArrowRight size={16} aria-hidden="true" />
              </button>
            </div>
          </div>
        ) : (
          <>
            <div className="user-form-intro">
              <h2>Network flow information</h2>
              <p>Use observed values. Required values are sent to the existing analysis API.</p>
            </div>
            {error && (
              <div className="user-form-alert error" role="alert">
                <AlertCircle size={18} aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}
            <form onSubmit={handleSubmit} className="user-event-form">
              <fieldset disabled={submitting}>
                <legend className="sr-only">Network event fields</legend>
                <div className="user-form-grid">
                  <EventField
                    id="source_ip"
                    label="Source IP address"
                    help="IPv4 or IPv6 address observed in the flow."
                    error={fieldErrors.source_ip}
                    type="text"
                    inputMode="text"
                    autoComplete="off"
                    spellCheck="false"
                    required
                    value={formData.source_ip}
                    onChange={updateField}
                    placeholder="For example, 192.0.2.10"
                  />
                  <EventField
                    id="destination_ip"
                    label="Destination IP address"
                    help="The destination address observed in the flow."
                    error={fieldErrors.destination_ip}
                    type="text"
                    inputMode="text"
                    autoComplete="off"
                    spellCheck="false"
                    required
                    value={formData.destination_ip}
                    onChange={updateField}
                    placeholder="For example, 198.51.100.20"
                  />
                  <EventField
                    id="source_port"
                    label="Source port"
                    help="Valid range: 0–65,535."
                    type="number"
                    min="0"
                    max="65535"
                    step="1"
                    required
                    value={formData.source_port}
                    onChange={updateField}
                    placeholder="Enter observed port"
                  />
                  <EventField
                    id="destination_port"
                    label="Destination port"
                    help="Use 1–65,535 to avoid the model's missing-value default."
                    type="number"
                    min="1"
                    max="65535"
                    step="1"
                    required
                    value={formData.destination_port}
                    onChange={updateField}
                    placeholder="Enter observed port"
                  />
                  <div className="user-form-field">
                    <label htmlFor="protocol">Protocol</label>
                    <select
                      id="protocol"
                      name="protocol"
                      required
                      value={formData.protocol}
                      onChange={updateField}
                      aria-describedby="protocol-help"
                    >
                      <option value="">Select a protocol</option>
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                      <option value="ICMP">ICMP</option>
                    </select>
                    <small id="protocol-help">Choose the protocol recorded for this flow.</small>
                  </div>
                  <EventField
                    id="duration"
                    label="Flow duration (milliseconds)"
                    help="Use a positive measured duration, up to 86,400,000 ms."
                    type="number"
                    min="0.001"
                    max="86400000"
                    step="any"
                    required
                    value={formData.duration}
                    onChange={updateField}
                    placeholder="Enter duration"
                  />
                  <EventField
                    id="packet_count"
                    label="Packet count"
                    help="Positive number of packets observed in the flow."
                    type="number"
                    min="1"
                    max="10000000"
                    step="1"
                    required
                    value={formData.packet_count}
                    onChange={updateField}
                    placeholder="Enter packet count"
                  />
                  <EventField
                    id="byte_count"
                    label="Byte count"
                    help="Positive number of bytes observed, up to 1,000,000,000."
                    type="number"
                    min="1"
                    max="1000000000"
                    step="1"
                    required
                    value={formData.byte_count}
                    onChange={updateField}
                    placeholder="Enter byte count"
                  />
                  <EventField
                    id="syn_flag_count"
                    label="SYN flag count (optional)"
                    help="If blank, the analysis API applies its documented default of 0."
                    type="number"
                    min="0"
                    max="10000000"
                    step="1"
                    value={formData.syn_flag_count}
                    onChange={updateField}
                    placeholder="Leave blank if unknown"
                  />
                  <EventField
                    id="ack_flag_count"
                    label="ACK flag count (optional)"
                    help="If blank, the analysis API applies its documented default of 1."
                    type="number"
                    min="0"
                    max="10000000"
                    step="1"
                    value={formData.ack_flag_count}
                    onChange={updateField}
                    placeholder="Leave blank if unknown"
                  />
                </div>
              </fieldset>
              <p className="user-form-disclaimer">
                Do not submit credentials, secrets, or personal data in event fields. The analysis is
                based on the flow values provided and is not external verification.
              </p>
              <div className="user-form-actions">
                <button className="btn btn-primary" type="submit" disabled={submitting}>
                  {submitting
                    ? <RefreshCw size={16} className="animate-spin" aria-hidden="true" />
                    : <Send size={16} aria-hidden="true" />}
                  {submitting ? 'Submitting and analyzing…' : 'Submit for analysis'}
                </button>
              </div>
            </form>
          </>
        )}
      </section>
    </div>
  );
};

export default SubmitEvent;
