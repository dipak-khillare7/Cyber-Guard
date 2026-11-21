import React from 'react';
import { Activity, AlertCircle, Cpu, ShieldCheck } from 'lucide-react';
import RiskBadge from '../common/RiskBadge';
import { formatDate } from '../../utils/formatDate';
import { formatConfidence, formatRiskScore } from '../../utils/formatRisk';
import { formatThreatLabel } from '../../utils/formatThreat';

const explanations = {
  DOS_DDOS: 'The submitted flow features resemble a denial-of-service traffic pattern.',
  PORT_SCAN: 'The submitted flow features resemble reconnaissance across network services.',
  BRUTE_FORCE: 'The submitted flow features resemble repeated authentication attempts.',
  WEB_ATTACK: 'The submitted flow features resemble activity commonly associated with a web attack.',
  BOTNET: 'The submitted flow features resemble traffic patterns associated with botnet activity.',
  INFILTRATION: 'The submitted flow features resemble activity associated with network infiltration.',
  NORMAL: 'No non-normal alert is linked to this event in the available history.',
};

const precautions = {
  DOS_DDOS: ['Review the relevant network and service logs.', 'Contact your network administrator if service availability is affected.'],
  PORT_SCAN: ['Review whether the connection attempts were expected.', 'Keep exposed services limited to those you need.'],
  BRUTE_FORCE: ['Review sign-in activity for the relevant account.', 'Use unique passwords and multi-factor authentication where available.'],
  WEB_ATTACK: ['Review the application logs with an administrator.', 'Keep the application and its dependencies updated.'],
  BOTNET: ['Run your approved endpoint protection checks.', 'Ask an administrator to review the device and its network activity.'],
  INFILTRATION: ['Treat this result as an indicator to review, not proof of compromise.', 'Ask a qualified administrator to inspect related logs.'],
  NORMAL: ['No alert is linked to this event; continue using your normal security controls.', 'A normal label does not guarantee that traffic is safe.'],
};

const UserResultDetails = ({ record, analysis }) => {
  const eventId = analysis?.event_id ?? record?.event_id ?? record?.id;
  const threat = analysis?.prediction?.threat_type
    || (record?.alert_id ? record.detected_threat : record?.detected_threat);
  const hasAlert = Boolean(analysis?.alert?.generated || record?.alert_id);
  const riskLevel = analysis?.risk?.level || (hasAlert ? record?.risk_level : null);
  const confidence = analysis?.prediction?.confidence
    ?? (hasAlert ? record?.confidence : null);
  const riskScore = analysis?.risk?.score ?? record?.risk_score;
  const reason = analysis?.risk?.reason || (hasAlert ? record?.message : null);
  const model = analysis?.model;
  const explanation = explanations[threat] || (
    hasAlert
      ? 'The model classified the submitted flow using its available network features.'
      : 'The history API reports no alert linked to this event and does not retain a per-event prediction.'
  );
  const recommendations = precautions[threat] || [
    'Review related activity with your network administrator if it was unexpected.',
    'Do not take disruptive action based only on an automated prediction.',
  ];

  if (!record && !analysis) return null;

  return (
    <div className="user-result-details">
      <section className="user-result-section" aria-labelledby="result-classification-heading">
        <div className="user-result-section-heading">
          <Cpu size={18} aria-hidden="true" />
          <h3 id="result-classification-heading">Machine-learning prediction</h3>
        </div>
        <div className="user-result-metrics">
          <div>
            <span className="user-result-label">Threat classification</span>
            <strong className="user-result-value">
              {threat
                ? (hasAlert || analysis ? formatThreatLabel(threat) : 'No alert linked')
                : 'Not available'}
            </strong>
          </div>
          <div>
            <span className="user-result-label">Model confidence</span>
            <strong className="user-result-value">
              {confidence === null || confidence === undefined
                ? 'Not retained in history'
                : formatConfidence(confidence)}
            </strong>
          </div>
          {model && (
            <div>
              <span className="user-result-label">Model</span>
              <strong className="user-result-value">{model.name} {model.version}</strong>
            </div>
          )}
        </div>
        <p className="user-result-explanation">{explanation}</p>
        {!analysis && !hasAlert && (
          <p className="user-result-caveat">
            The history API labels events without an associated alert as NORMAL. It does not retain a
            per-event confidence for those records.
          </p>
        )}
      </section>

      <section className="user-result-section" aria-labelledby="result-risk-heading">
        <div className="user-result-section-heading risk-heading">
          <AlertCircle size={18} aria-hidden="true" />
          <h3 id="result-risk-heading">Rule-based risk assessment</h3>
        </div>
        <div className="user-result-metrics">
          <div>
            <span className="user-result-label">Risk level</span>
            {riskLevel ? <RiskBadge level={riskLevel} /> : <strong>Not retained in history</strong>}
          </div>
          <div>
            <span className="user-result-label">Risk score</span>
            <strong className="user-result-value">
              {riskScore === null || riskScore === undefined
                ? 'Not retained in history'
                : formatRiskScore(riskScore)}
            </strong>
          </div>
        </div>
        {reason && <p className="user-result-explanation">{reason}</p>}
      </section>

      <section className="user-result-section" aria-labelledby="result-event-heading">
        <div className="user-result-section-heading">
          <Activity size={18} aria-hidden="true" />
          <h3 id="result-event-heading">Submitted event</h3>
        </div>
        <dl className="user-event-details">
          <div><dt>Event ID</dt><dd>{eventId ? `#${eventId}` : 'Not available'}</dd></div>
          <div><dt>Submitted</dt><dd>{record?.timestamp ? formatDate(record.timestamp) : 'Timestamp not returned by analysis response'}</dd></div>
          <div><dt>Source IP</dt><dd>{record?.source_ip ?? 'Not provided'}</dd></div>
          <div><dt>Destination IP</dt><dd>{record?.destination_ip ?? 'Not provided'}</dd></div>
          <div><dt>Source port</dt><dd>{record?.source_port ?? 'Not provided'}</dd></div>
          <div><dt>Destination port</dt><dd>{record?.destination_port ?? 'Not provided'}</dd></div>
          <div><dt>Protocol</dt><dd>{record?.protocol ?? 'Not provided'}</dd></div>
          <div><dt>Flow duration</dt><dd>{record?.duration ?? 'Not provided'}</dd></div>
          <div><dt>Packets</dt><dd>{record?.packet_count ?? 'Not provided'}</dd></div>
          <div><dt>Bytes</dt><dd>{record?.byte_count ?? 'Not provided'}</dd></div>
        </dl>
      </section>

      <section className="user-result-section" aria-labelledby="result-precautions-heading">
        <div className="user-result-section-heading">
          <ShieldCheck size={18} aria-hidden="true" />
          <h3 id="result-precautions-heading">Suggested precautions</h3>
        </div>
        <ul className="user-precautions">
          {recommendations.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}
        </ul>
      </section>

      {analysis?.response?.action_status && analysis.response.action_status !== 'NONE' && (
        <p className="user-result-caveat">
          Any response shown by the analysis is simulated. It does not block or change network traffic.
        </p>
      )}

      <p className="user-evidence-disclaimer">
        <strong>Evidence note:</strong> This result analyzes the flow fields you submitted. It is not a
        live network scan or a confirmed compromise, and no external reputation or network evidence is
        attached to this result.
      </p>
    </div>
  );
};

export default UserResultDetails;
