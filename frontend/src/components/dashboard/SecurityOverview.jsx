import React from 'react';
import {
  Activity,
  AlertTriangle,
  ShieldAlert,
  Zap,
  Layers,
  AlertCircle,
  ShieldCheck,
  CheckCircle2,
  Clock3,
} from 'lucide-react';
import StatCard from '../StatCard';

const SecurityOverview = ({ stats }) => {
  return (
    <div className="stats-grid">
      <StatCard
        title="Total Events"
        value={stats?.total_events}
        icon={Activity}
        color="var(--accent-blue)"
      />
      <StatCard
        title="Normal / No Threat Alert"
        value={stats?.normal_events}
        note="No non-normal alert linked; not proof of safe traffic"
        icon={ShieldCheck}
        color="var(--accent-emerald)"
      />
      <StatCard
        title="Suspicious Events"
        value={stats?.suspicious_events}
        note="Unique events with a non-normal alert"
        icon={AlertTriangle}
        color="var(--accent-amber)"
      />
      <StatCard
        title="Total Alerts"
        value={stats?.total_alerts}
        icon={Layers}
        color="var(--accent-purple)"
      />
      <StatCard
        title="Active Alerts"
        value={stats?.active_alerts}
        icon={AlertCircle}
        color="var(--accent-rose)"
      />
      <StatCard
        title="High-Risk Alerts"
        value={stats?.high_threats}
        icon={ShieldAlert}
        color="#f97316"
      />
      <StatCard
        title="Critical Alerts"
        value={stats?.critical_threats}
        icon={Zap}
        color="var(--accent-rose)"
      />
      <StatCard
        title="Total Incidents"
        value={stats?.total_incidents}
        icon={ShieldAlert}
        color="var(--accent-purple)"
      />
      <StatCard
        title="Open Incidents"
        value={stats?.open_incidents}
        icon={Clock3}
        color="var(--accent-amber)"
      />
      <StatCard
        title="Resolved / Closed Incidents"
        value={stats?.resolved_incidents}
        icon={CheckCircle2}
        color="var(--accent-emerald)"
      />
    </div>
  );
};

export default SecurityOverview;
