import React from 'react';

const labels = {
  LOW: 'Low risk indicator',
  MEDIUM: 'Medium risk indicator',
  HIGH: 'High risk indicator',
  CRITICAL: 'Critical risk indicator',
  INSUFFICIENT_INFORMATION: 'Insufficient information',
  ANALYSIS_UNAVAILABLE: 'Analysis unavailable',
};

const WebsiteRiskBadge = ({ level }) => (
  <span className={`website-risk-badge website-risk-${level?.toLowerCase() || 'unknown'}`}>
    {labels[level] || 'Assessment unavailable'}
  </span>
);

export default WebsiteRiskBadge;
