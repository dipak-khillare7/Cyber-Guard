import { useState, useEffect, useCallback } from 'react';
import { incidentService } from '../services/incidentService';

export const useIncidents = (params = {}) => {
  const [data, setData] = useState({ items: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const { page = 1, limit = 15, risk_level, severity, ...restParams } = params;
  const skip = (page - 1) * limit;
  const apiParams = { skip, limit, severity: severity || risk_level, ...restParams };

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await incidentService.getIncidents(apiParams);
      setData(response.data);
    } catch (err) {
      setError(err.response?.data?.error?.message || err.message || 'Error fetching incidents');
    } finally {
      setLoading(false);
    }
  }, [JSON.stringify(apiParams)]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  const items = data.items || data.data?.items || (Array.isArray(data) ? data : []);
  const totalItems = data.total ?? data.data?.total ?? items.length;

  return {
    data,
    incidents: items,
    total: totalItems,
    skip: data.skip || skip,
    limit: data.limit || limit,
    pages: Math.max(1, Math.ceil(totalItems / (data.limit || limit))),
    loading,
    error,
    refetch: fetchIncidents,
    refresh: fetchIncidents
  };
};

