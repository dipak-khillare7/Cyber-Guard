import React, { useState } from 'react';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import { useFetch } from '../hooks/useFetch';
import { eventService } from '../services/api';
import { formatDate } from '../utils/formatters';
import { PlusCircle, RefreshCw } from 'lucide-react';

const Events = () => {
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const { data, loading, error, refetch } = useFetch(
    () => eventService.getEvents({ limit: 50, event_type: eventTypeFilter || undefined }),
    [eventTypeFilter]
  );

  const handleSimulateEvent = async () => {
    try {
      await eventService.createEvent({
        source_ip: '192.168.1.105',
        destination_ip: '10.0.0.1',
        source_port: 51234,
        destination_port: 80,
        protocol: 'TCP',
        packet_count: 1500,
        event_type: 'NETWORK',
        raw_data: 'Simulated HTTP flood traffic sample'
      });
      refetch();
    } catch (err) {
      alert('Error creating event: ' + err.message);
    }
  };

  if (loading) return <LoadingState message="Loading security events log..." />;
  if (error) return <ErrorState message={error} onRetry={refetch} />;

  const columns = [
    { header: 'ID', accessor: 'id', width: '60px' },
    { header: 'Timestamp', accessor: 'timestamp', render: (r) => <span className="font-mono">{formatDate(r.timestamp)}</span> },
    { header: 'Source IP', accessor: 'source_ip', render: (r) => <span className="font-mono">{r.source_ip || '-'}</span> },
    { header: 'Dest IP', accessor: 'destination_ip', render: (r) => <span className="font-mono">{r.destination_ip || '-'}</span> },
    { header: 'Src Port', accessor: 'source_port', render: (r) => <span className="font-mono">{r.source_port || '-'}</span> },
    { header: 'Dst Port', accessor: 'destination_port', render: (r) => <span className="font-mono">{r.destination_port || '-'}</span> },
    { header: 'Protocol', accessor: 'protocol' },
    { header: 'Packets', accessor: 'packet_count', render: (r) => <span className="font-mono">{r.packet_count || 0}</span> },
    { header: 'Event Type', accessor: 'event_type' },
  ];

  return (
    <div>
      <PageHeader
        title="Security Events Log"
        description="Ingested raw network flows and system security log events."
      >
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-secondary" onClick={refetch} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> {loading ? 'Refreshing...' : 'Refresh'}
          </button>
          <button className="btn btn-primary" onClick={handleSimulateEvent} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <PlusCircle size={16} /> Ingest Sample Event
          </button>
        </div>
      </PageHeader>

      <div className="table-card">
        <div className="table-header">
          <div className="table-title">Events ({data?.total || 0})</div>
          <select
            value={eventTypeFilter}
            onChange={(e) => setEventTypeFilter(e.target.value)}
            style={{
              backgroundColor: 'var(--bg-secondary)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-sm)',
              padding: '0.4rem 0.8rem'
            }}
          >
            <option value="">All Event Types</option>
            <option value="NETWORK">NETWORK</option>
            <option value="SYSTEM">SYSTEM</option>
            <option value="AUTH">AUTH</option>
            <option value="LOG">LOG</option>
          </select>
        </div>
        <DataTable
          columns={columns}
          data={data?.items || []}
          emptyMessage="No security events recorded in database yet."
        />
      </div>
    </div>
  );
};

export default Events;
