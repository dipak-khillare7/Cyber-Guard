import { useState, useEffect, useCallback } from 'react';
import { statisticsService } from '../services/statisticsService';
import { detectionService } from '../services/detectionService';
import { REFRESH_INTERVAL_MS } from '../utils/constants';

export const useStatistics = (autoRefresh = true) => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchStats = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, trendRes] = await Promise.all([
        statisticsService.getStatistics(),
        detectionService.getDetectionTrend(24).catch(() => ({ data: { trend: [] } }))
      ]);

      const baseStats = statsRes.data?.data || statsRes.data || {};
      const trendData = trendRes.data?.trend || trendRes.data?.data?.trend || [];

      setStats({
        ...baseStats,
        detection_trend: trendData
      });
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.response?.data?.error?.message || err.message || 'Failed to connect to backend statistics API');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    if (autoRefresh) {
      const interval = setInterval(fetchStats, REFRESH_INTERVAL_MS);
      return () => clearInterval(interval);
    }
  }, [fetchStats, autoRefresh]);

  return { stats, loading, error, lastUpdated, refetch: fetchStats, refresh: fetchStats };
};
