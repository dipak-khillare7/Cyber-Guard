import React from 'react';
import { AlertTriangle, CheckCircle2, Clock3, Globe2, ShieldCheck } from 'lucide-react';
import { formatDate } from '../../utils/formatDate';
import WebsiteRiskBadge from './WebsiteRiskBadge';

const formatStatus = (value) => (value || 'NOT_CHECKED').replaceAll('_', ' ');

const WebsiteAssessmentDetails = ({ assessment }) => {
  if (!assessment) return null;

  const dnsFindings = assessment.dns_findings || {};
  const dnsRecords = dnsFindings.records || {};
  const dnsRecordStatus = dnsFindings.record_status || {};
  const noRecordsMessage = (recordType) => (
    dnsRecordStatus[recordType] === 'NO_RECORD'
      ? 'No records returned'
      : dnsRecordStatus[recordType] ? formatStatus(dnsRecordStatus[recordType]) : 'Not checked'
  );
  const policyRecordMessage = (records, sourceType, label) => (
    records?.length
      ? records.join('; ')
      : dnsRecordStatus[sourceType] === 'AVAILABLE' ? `No ${label} record found` : noRecordsMessage(sourceType)
  );
  const providerStatusText = {
    FOUND: 'Report found',
    NO_RECORD: 'No report found',
    NOT_CONFIGURED: 'Provider is not configured',
    RATE_LIMITED: 'Provider rate limit reached',
    AUTHENTICATION_ERROR: 'Provider credentials are unavailable',
    PROVIDER_FORBIDDEN: 'Provider access is unavailable',
    TIMEOUT: 'Provider timed out',
    UNAVAILABLE: 'Provider is unavailable',
  }[assessment.provider_status] || 'Provider was not queried';

  return (
    <div className="website-assessment-details">
      <section className="user-result-section">
        <div className="user-result-section-heading">
          <Globe2 size={18} aria-hidden="true" />
          <h3>Website result</h3>
        </div>
        <div className="website-assessment-summary">
          <WebsiteRiskBadge level={assessment.risk_level} />
          <p>{assessment.risk_explanation}</p>
        </div>
        <dl className="user-event-details">
          <div><dt>Website</dt><dd>{assessment.target_domain}</dd></div>
          <div><dt>Checked</dt><dd>{formatDate(assessment.created_at)}</dd></div>
          <div><dt>Analysis status</dt><dd>{formatStatus(assessment.analysis_status)}</dd></div>
          <div><dt>Analysis engine</dt><dd>{assessment.engine_version || 'legacy'}</dd></div>
          <div><dt>Scoring method</dt><dd>{assessment.scoring_version || 'legacy'}</dd></div>
          <div>
            <dt>Risk score</dt>
            <dd>{typeof assessment.risk_score === 'number' ? `${assessment.risk_score}/100` : 'Not scored'}</dd>
          </div>
        </dl>
        {assessment.scoring_version === 'website-risk-v1' ? (
          <p className="user-result-explanation">
            Scoring policy: malicious provider detections add 60–75 points, suspicious detections add
            30–50 points, and failed TLS certificate verification adds 25 points. Levels change at
            25, 60, and 85 points. Missing checks add no points.
          </p>
        ) : (
          <p className="user-result-explanation">
            This is a legacy result; the current versioned scoring policy was not applied.
          </p>
        )}
      </section>

      <section className="user-result-section">
        <div className="user-result-section-heading">
          <ShieldCheck size={18} aria-hidden="true" />
          <h3>Threat intelligence</h3>
        </div>
        <p className="user-result-explanation">
          VirusTotal status: <strong>{providerStatusText}</strong>. Provider reputation is not
          independent confirmation that a website is malicious or safe.
        </p>
        {assessment.vendor_count !== null && assessment.vendor_count !== undefined ? (
          <dl className="website-vendor-stats">
            <div><dt>Malicious reports</dt><dd>{assessment.malicious_count ?? 'Not reported'}</dd></div>
            <div><dt>Suspicious reports</dt><dd>{assessment.suspicious_count ?? 'Not reported'}</dd></div>
            <div><dt>Harmless reports</dt><dd>{assessment.harmless_count ?? 'Not reported'}</dd></div>
            <div><dt>Undetected</dt><dd>{assessment.undetected_count ?? 'Not reported'}</dd></div>
            <div><dt>Vendors in analysis</dt><dd>{assessment.vendor_count}</dd></div>
            <div>
              <dt>Provider analysis time</dt>
              <dd>{assessment.provider_analysis_at ? formatDate(assessment.provider_analysis_at) : 'Not reported'}</dd>
            </div>
          </dl>
        ) : (
          <p className="website-evidence-empty">
            <AlertTriangle size={16} aria-hidden="true" />
            No vendor analysis statistics are available for this check.
          </p>
        )}
      </section>

      <section className="user-result-section">
        <div className="user-result-section-heading">
          <Clock3 size={18} aria-hidden="true" />
          <h3>DNS analysis: {formatStatus(assessment.dns_status)}</h3>
        </div>
        <dl className="website-vendor-stats">
          <div>
            <dt>Normalized domain</dt>
            <dd>{dnsFindings.normalized_domain || assessment.target_domain}</dd>
          </div>
          <div>
            <dt>Domain format</dt>
            <dd>{dnsFindings.domain_format_valid === true ? 'Valid' : 'Not verified'}</dd>
          </div>
          <div>
            <dt>Address resolution</dt>
            <dd>{formatStatus(dnsFindings.dns_resolution_status)}</dd>
          </div>
          {Object.entries(dnsRecordStatus).map(([recordType, recordStatus]) => (
            <div key={recordType}>
              <dt>{recordType} status</dt>
              <dd>{formatStatus(recordStatus)}</dd>
            </div>
          ))}
          {Object.entries(dnsRecords).map(([recordType, values]) => (
            <div key={`${recordType}-records`}>
              <dt>{recordType} records</dt>
              <dd>{Array.isArray(values) && values.length ? values.map((value) => (
                typeof value === 'string' ? value : JSON.stringify(value)
              )).join(', ') : noRecordsMessage(recordType)}</dd>
            </div>
          ))}
          <div>
            <dt>Public addresses</dt>
            <dd>{dnsFindings.addresses?.length ? dnsFindings.addresses.join(', ') : 'Not available'}</dd>
          </div>
          <div>
            <dt>SPF</dt>
            <dd>{policyRecordMessage(dnsFindings.spf, 'TXT', 'SPF')}</dd>
          </div>
          <div>
            <dt>DMARC</dt>
            <dd>{policyRecordMessage(dnsFindings.dmarc, 'DMARC', 'DMARC')}</dd>
          </div>
        </dl>
        <p className="user-result-explanation">
          Missing DNS records are not treated as proof that a website is malicious.
          Registration data: {formatStatus(dnsFindings.registration_status || 'NOT_CONFIGURED')}.
        </p>
      </section>

      <section className="user-result-section">
        <div className="user-result-section-heading">
          <CheckCircle2 size={18} aria-hidden="true" />
          <h3>TLS certificate: {formatStatus(assessment.ssl_status)}</h3>
        </div>
        <dl className="user-event-details">
          <div>
            <dt>Certificate valid</dt>
            <dd>{assessment.ssl_findings?.certificate_valid === true
              ? 'Yes'
              : assessment.ssl_findings?.certificate_valid === false ? 'No' : 'Not verified'}</dd>
          </div>
          <div>
            <dt>Hostname match</dt>
            <dd>{assessment.ssl_findings?.hostname_match === true
              ? 'Yes'
              : assessment.ssl_findings?.hostname_match === false ? 'No' : 'Not verified'}</dd>
          </div>
          {assessment.ssl_findings?.expires_at && (
            <div><dt>Certificate expires</dt><dd>{formatDate(assessment.ssl_findings.expires_at)}</dd></div>
          )}
          {assessment.ssl_findings?.issuer && (
            <div><dt>Issuer</dt><dd>{assessment.ssl_findings.issuer}</dd></div>
          )}
          {assessment.ssl_findings?.tls_version && (
            <div><dt>TLS version</dt><dd>{assessment.ssl_findings.tls_version}</dd></div>
          )}
          {assessment.ssl_findings?.reason && (
            <div><dt>Result detail</dt><dd>{assessment.ssl_findings.reason}</dd></div>
          )}
        </dl>
      </section>

      {assessment.evidence?.length > 0 && (
        <section className="user-result-section">
          <div className="user-result-section-heading">
            <ShieldCheck size={18} aria-hidden="true" />
            <h3>Evidence</h3>
          </div>
          <ul className="user-precautions">
            {assessment.evidence.map((item, index) => (
              <li key={`${item.type || 'evidence'}-${index}`}>
                {item.description || `${item.type || 'Evidence'}: ${JSON.stringify(item)}`}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="user-result-section">
        <div className="user-result-section-heading">
          <AlertTriangle size={18} aria-hidden="true" />
          <h3>Risk factors</h3>
        </div>
        {assessment.risk_factors?.length ? (
          <ul className="user-precautions">
            {assessment.risk_factors.map((factor) => (
              <li key={factor.code}>
                {factor.description} ({factor.points} points)
              </li>
            ))}
          </ul>
        ) : <p className="user-result-explanation">No risk-increasing evidence factors were identified.</p>}
        {assessment.risk_reducing_factors?.length > 0 && (
          <>
            <h4>Potentially reassuring observations</h4>
            <ul className="user-precautions">
              {assessment.risk_reducing_factors.map((factor) => (
                <li key={factor.code}>{factor.description}</li>
              ))}
            </ul>
          </>
        )}
      </section>

      <section className="user-result-section">
        <div className="user-result-section-heading">
          <AlertTriangle size={18} aria-hidden="true" />
          <h3>Limitations and recommendations</h3>
        </div>
        <h4>Limitations</h4>
        <ul className="user-precautions">
          {(assessment.limitations || []).map((limitation, index) => (
            <li key={`limitation-${index}`}>{limitation}</li>
          ))}
        </ul>
        <h4>Recommendations</h4>
        {assessment.recommendations?.length ? (
          <ul className="user-precautions">
            {assessment.recommendations.map((recommendation, index) => (
              <li key={`recommendation-${index}`}>{recommendation}</li>
            ))}
          </ul>
        ) : <p className="user-result-explanation">No recommendation data was stored for this record.</p>}
      </section>

      <p className="user-evidence-disclaimer">
        Only the website origin and normalized findings are stored; URL paths and query strings are not
        stored by this application. The URL was shared with VirusTotal only after consent and may be
        retained by that provider under its terms.
      </p>
    </div>
  );
};

export default WebsiteAssessmentDetails;
