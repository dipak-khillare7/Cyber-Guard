import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import SecurityOverview from '../components/dashboard/SecurityOverview';
import ThreatDistributionChart from '../components/dashboard/ThreatDistributionChart';
import RiskSummaryChart from '../components/dashboard/RiskSummaryChart';
import DetectionTrendChart from '../components/dashboard/DetectionTrendChart';
import AnalyzeEventFormModal from '../components/detections/AnalyzeEventFormModal';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import RiskBadge from '../components/common/RiskBadge';
import StatusBadge from '../components/common/StatusBadge';
import { useStatistics } from '../hooks/useStatistics';
import { useAlerts } from '../hooks/useAlerts';
import { useIncidents } from '../hooks/useIncidents';
import { eventService } from '../services/eventService';
import { formatDate } from '../utils/formatDate';
import { formatThreatLabel } from '../utils/formatThreat';
import { useAuth } from '../context/AuthContext';
import { Activity, AlertTriangle, Eye, Plus, RefreshCw, ShieldAlert } from 'lucide-react';

const Dashboard = () => {
  const {
    stats,
    trendData,
    loading: statsLoading,
    error: statsError,
    trendError,
    refetch: refreshStats,
  } = useStatistics();
  const { role } = useAuth();
  const {
    alerts,
    loading: alertsLoading,
    error: alertsError,
    refresh: refreshAlerts,
  } = useAlerts({ page: 1, limit: 100 });
  const {
    incidents,
    loading: incidentsLoading,
    error: incidentsError,
    refresh: refreshIncidents,
  } = useIncidents({ page: 1, limit: 5 });
  const [recentEvents, setRecentEvents] = useState([]);
  const [eventsLoading, setEventsLoading] = useState(true);
  const [eventsError, setEventsError] = useState(null);
  const [isAnalyzeModalOpen, setIsAnalyzeModalOpen] = useState(false);

  const refreshEvents = useCallback(async () => {
    setEventsLoading(true);
    setEventsError(null);
    try {
      const response = await eventService.getEvents({ skip: 0, limit: 8 });
      const payload = response.data?.data || response.data || {};
      setRecentEvents(Array.isArray(payload.items) ? payload.items : []);
    } catch (error) {
      setEventsError(error.message || 'Unable to load recent security events.');
    } finally {
      setEventsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshEvents();
  }, [refreshEvents]);

  const alertsByEventId = useMemo(
    () => new Map(alerts.filter((alert) => alert.event_id != null).map((alert) => [alert.event_id, alert])),
    [alerts],
  );

  const isRefreshing = statsLoading || eventsLoading || alertsLoading || incidentsLoading;
  const handleRefresh = () => {
    refreshStats();
    refreshEvents();
    refreshAlerts();
    refreshIncidents();
  };

  if (statsLoading && !stats) {
    return <LoadingState message="Loading SOC overview from platform data..." />;
  }

  if (statsError && !stats) {
    return <ErrorState message={statsError} onRetry={handleRefresh} />;
  }

  return (
    <div className="soc-dashboard">
      <header className="page-header soc-dashboard-header">
        <div>
          <p className="soc-eyebrow">SECURITY OPERATIONS CENTER</p>
          <h1 className="page-title">SOC Overview</h1>
          <p className="page-description">
            {role === 'ADMIN'
              ? 'Platform-wide event, alert, and incident activity from backend records.'
              : 'Your event, alert, and incident activity from backend records.'}
          </p>
        </div>
        <div className="soc-dashboard-actions">
          <button className="btn btn-secondary" type="button" onClick={handleRefresh} disabled={isRefreshing}>
            <RefreshCw size={16} className={isRefreshing ? 'animate-spin' : ''} aria-hidden="true" />
            {isRefreshing ? 'Refreshing…' : 'Refresh'}
          </button>
          <button className="btn btn-primary" type="button" onClick={() => setIsAnalyzeModalOpen(true)}>
            <Plus size={16} aria-hidden="true" />
            Analyze New Event
          </button>
        </div>
      </header>

      {statsError && (
        <p className="soc-inline-error" role="status">
          Statistics refresh failed. Showing the last successfully loaded metrics. {statsError}
        </p>
      )}

      <section aria-label="Security operations metrics">
        <SecurityOverview stats={stats?.overview || stats} />
      </section>

      <section className="soc-chart-grid" aria-label="Threat and risk distributions">
        <ThreatDistributionChart data={stats?.threats_by_type || {}} />
        <RiskSummaryChart data={stats?.threats_by_severity || {}} />
      </section>

      <DetectionTrendChart trendData={trendData} error={trendError} />

      <section className="table-card soc-dashboard-panel" aria-labelledby="recent-events-heading">
        <div className="table-header">
          <div className="soc-panel-title">
            <Activity size={18} aria-hidden="true" />
            <div>
              <h2 id="recent-events-heading" className="table-title">Recent Security Events</h2>
              <p>Latest stored events. An alert association appears when it is present in the recent alert feed.</p>
            </div>
          </div>
          <Link className="soc-panel-link" to="/detections">Threat detection <Eye size={14} aria-hidden="true" /></Link>
        </div>
        {eventsLoading && recentEvents.length === 0 ? (
          <LoadingState message="Loading recent events..." />
        ) : eventsError ? (
          <ErrorState message={eventsError} onRetry={refreshEvents} />
        ) : recentEvents.length === 0 ? (
          <p className="soc-empty-state">No security events have been recorded.</p>
        ) : (
          <div className="soc-table-wrap">
            <table className="data-table soc-events-table">
              <caption className="sr-only">Recent security events</caption>
              <thead>
                <tr>
                  <th scope="col">Event</th>
                  <th scope="col">Timestamp</th>
                  <th scope="col">Network flow</th>
                  <th scope="col">Protocol</th>
                  <th scope="col">Detection</th>
                  <th scope="col">Risk</th>
                </tr>
              </thead>
              <tbody>
                {recentEvents.map((event) => {
                  const linkedAlert = alertsByEventId.get(event.id);
                  return (
                    <tr key={event.id}>
                      <td className="font-mono">#{event.id}</td>
                      <td>{formatDate(event.timestamp || event.created_at)}</td>
                      <td className="font-mono">
                        {event.source_ip || '—'} <span aria-hidden="true">→</span> {event.destination_ip || '—'}
                      </td>
                      <td>{event.protocol || '—'}</td>
                      <td>{linkedAlert ? formatThreatLabel(linkedAlert.threat_type) : 'No recent match'}</td>
                      <td>{linkedAlert ? <RiskBadge level={linkedAlert.risk_level} /> : '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="soc-recent-grid">
        <section className="table-card soc-dashboard-panel" aria-labelledby="recent-alerts-heading">
          <div className="table-header">
            <div className="soc-panel-title">
              <AlertTriangle size={18} aria-hidden="true" />
              <div>
                <h2 id="recent-alerts-heading" className="table-title">Recent Alerts</h2>
                <p>Latest alert records. Repeated activity may update an existing alert.</p>
              </div>
            </div>
            <Link className="soc-panel-link" to="/alerts">All alerts <Eye size={14} aria-hidden="true" /></Link>
          </div>
          {alertsLoading && alerts.length === 0 ? (
            <LoadingState message="Loading recent alerts..." />
          ) : alertsError ? (
            <ErrorState message={alertsError} onRetry={refreshAlerts} />
          ) : alerts.length === 0 ? (
            <p className="soc-empty-state">No alert records are available.</p>
          ) : (
            <div className="soc-table-wrap">
              <table className="data-table soc-compact-table">
                <caption className="sr-only">Latest security alerts</caption>
                <thead>
                  <tr>
                    <th scope="col">Alert</th>
                    <th scope="col">Category</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Status</th>
                    <th scope="col">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 5).map((alert) => (
                    <tr key={alert.id}>
                      <td className="font-mono">#{alert.id}{alert.event_id ? ` / Event #${alert.event_id}` : ''}</td>
                      <td>{formatThreatLabel(alert.threat_type)}</td>
                      <td><RiskBadge level={alert.risk_level} /></td>
                      <td><StatusBadge status={alert.status} /></td>
                      <td>{formatDate(alert.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="table-card soc-dashboard-panel" aria-labelledby="recent-incidents-heading">
          <div className="table-header">
            <div className="soc-panel-title">
              <ShieldAlert size={18} aria-hidden="true" />
              <div>
                <h2 id="recent-incidents-heading" className="table-title">Recent Incidents</h2>
                <p>Latest incident records and current response status.</p>
              </div>
            </div>
            <Link className="soc-panel-link" to="/incidents">All incidents <Eye size={14} aria-hidden="true" /></Link>
          </div>
          {incidentsLoading && incidents.length === 0 ? (
            <LoadingState message="Loading recent incidents..." />
          ) : incidentsError ? (
            <ErrorState message={incidentsError} onRetry={refreshIncidents} />
          ) : incidents.length === 0 ? (
            <p className="soc-empty-state">No incident records are available.</p>
          ) : (
            <div className="soc-table-wrap">
              <table className="data-table soc-compact-table">
                <caption className="sr-only">Latest security incidents</caption>
                <thead>
                  <tr>
                    <th scope="col">Incident</th>
                    <th scope="col">Category</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Status</th>
                    <th scope="col">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((incident) => (
                    <tr key={incident.id}>
                      <td className="font-mono">#{incident.id}</td>
                      <td>{formatThreatLabel(incident.threat_type)}</td>
                      <td><RiskBadge level={incident.severity} /></td>
                      <td><StatusBadge status={incident.status} /></td>
                      <td>{formatDate(incident.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      <p className="soc-evidence-note">
        Event and alert records reflect automated model and rule outputs. They are investigative indicators,
        not independently confirmed malicious activity. Events without a linked alert are not guaranteed safe.
      </p>

      {isAnalyzeModalOpen && (
        <AnalyzeEventFormModal
          isOpen={isAnalyzeModalOpen}
          onClose={() => setIsAnalyzeModalOpen(false)}
          onSuccess={handleRefresh}
        />
      )}
    </div>
  );
};

export default Dashboard;
