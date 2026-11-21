import React from 'react';
import { ArrowRight, Globe2, Shield } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { getPortalOptions } from '../utils/portalAccess';
import AnalystAccessRequest from '../components/common/AnalystAccessRequest';

const FEATURES = {
  user: [
    'Website security checking',
    'Website risk assessments',
    'Security explanations and recommendations',
    'Personal analysis history and previous results',
  ],
  analyst: [
    'SOC overview and network event analysis',
    'ML-based threat classification and risk scoring',
    'Security alerts and incident management',
    'Simulated response actions and investigation history',
  ],
};

const DashboardSelect = () => {
  const { user } = useAuth();
  const portals = getPortalOptions(user?.role, user?.permissions);

  return (
    <section className="dashboard-select-page">
      <header className="dashboard-select-header">
        <p className="user-eyebrow">WORKSPACE</p>
        <h1>Welcome to Cyber Guard</h1>
        <p>Choose the workspace you want to access.</p>
      </header>
      <div className={`dashboard-select-grid${portals.length === 1 ? ' single' : ''}`}>
        {portals.map((portal) => {
          const Icon = portal.id === 'user' ? Globe2 : Shield;
          return (
            <article key={portal.id} className={`dashboard-select-card dashboard-select-${portal.id}`}>
              <span className="dashboard-select-icon"><Icon size={25} aria-hidden="true" /></span>
              <h2>{portal.id === 'user' ? 'Normal User Dashboard' : portal.label}</h2>
              <p>
                {portal.id === 'user'
                  ? 'Check website safety and understand potential security risks through a simple interface.'
                  : 'Investigate network security events, analyze threats, and manage security incidents.'}
              </p>
              <ul>
                {FEATURES[portal.id].map((feature) => <li key={feature}>{feature}</li>)}
              </ul>
              <Link className="dashboard-select-action" to={portal.path}>
                {portal.id === 'user' ? 'Continue as Normal User' : 'Continue as Analyst'}
                <ArrowRight size={17} aria-hidden="true" />
              </Link>
            </article>
          );
        })}
      </div>
      {portals.length === 0 && (
        <p className="dashboard-select-empty" role="status">
          No workspace is currently authorized for this account. Contact an administrator for access.
        </p>
      )}
      {user?.role === 'VIEWER' && <AnalystAccessRequest />}
      <p className="dashboard-select-security-note">
        Available workspaces are based on your account permissions. Choosing a workspace does not change your role.
      </p>
    </section>
  );
};

export default DashboardSelect;
