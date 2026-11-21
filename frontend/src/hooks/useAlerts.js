import { useState, useEffect, useCallback } from 'react';
import { alertService } from '../services/alertService';

export const useAlerts = (params = {}) => {
  const [data, setData] = useState({ items: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const { page = 1, limit = 15, ...restParams } = params;
  const skip = (page - 1) * limit;
  const apiParams = { skip, limit, ...restParams };

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await alertService.getAlerts(apiParams);
      setData(response.data);
    } catch (err) {
      setError(err.response?.data?.error?.message || err.message || 'Error fetching alerts');
    } finally {
      setLoading(false);
    }
  }, [JSON.stringify(apiParams)]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const items = data.items || data.data?.items || (Array.isArray(data) ? data : []);
  const totalItems = data.total ?? data.data?.total ?? items.length;

  return {
    data,
    alerts: items,
    total: totalItems,
    skip: data.skip || skip,
    limit: data.limit || limit,
    pages: Math.max(1, Math.ceil(totalItems / (data.limit || limit))),
    loading,
    error,
    refetch: fetchAlerts,
    refresh: fetchAlerts
  };
};

