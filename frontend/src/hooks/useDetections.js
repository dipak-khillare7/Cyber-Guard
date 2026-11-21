import { useState, useEffect, useCallback } from 'react';
import { detectionService } from '../services/detectionService';

export const useDetections = (params = {}) => {
  const [data, setData] = useState({ items: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const { page = 1, limit = 15, ...restParams } = params;
  const skip = (page - 1) * limit;
  const apiParams = { skip, limit, ...restParams };

  const fetchDetections = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await detectionService.getDetectionHistory(apiParams);
      setData(response.data);
    } catch (err) {
      setError(err.response?.data?.error?.message || err.message || 'Error fetching detection history');
    } finally {
      setLoading(false);
    }
  }, [JSON.stringify(apiParams)]);

  useEffect(() => {
    fetchDetections();
  }, [fetchDetections]);

  const items = data.items || data.data?.items || (Array.isArray(data) ? data : []);
  const totalItems = data.total ?? data.data?.total ?? items.length;

  return {
    data,
    detections: items,
    total: totalItems,
    skip: data.skip || skip,
    limit: data.limit || limit,
    pages: Math.max(1, Math.ceil(totalItems / (data.limit || limit))),
    loading,
    error,
    refetch: fetchDetections,
    refresh: fetchDetections
  };
};
