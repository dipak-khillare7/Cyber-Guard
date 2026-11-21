import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

const DetectionTrendChart = ({ trendData = [] }) => {
  if (!trendData || trendData.length === 0) {
    return (
      <div className="table-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
        <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', fontWeight: 600 }}>24-Hour Detection Trend</h3>
        <p className="empty-state">No detection trend data available.</p>
      </div>
    );
  }

  return (
    <div className="table-card" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
      <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', fontWeight: 600 }}>
        24-Hour Event & Detection Trend
      </h3>
      <div style={{ width: '100%', height: 240 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={trendData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="normalGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4}/>
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.5} />
            <XAxis dataKey="time" stroke="#9ca3af" fontSize={11} tickLine={false} />
            <YAxis stroke="#9ca3af" fontSize={11} tickLine={false} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f9fafb', borderRadius: '8px' }}
              labelFormatter={(label) => `Time Window: ${label} IST`}
            />
            <Area type="monotone" dataKey="threats" name="Threat Detections" stroke="#ef4444" fillOpacity={1} fill="url(#threatGradient)" />
            <Area type="monotone" dataKey="normal" name="Normal Traffic" stroke="#3b82f6" fillOpacity={1} fill="url(#normalGradient)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default DetectionTrendChart;
