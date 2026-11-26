import { useState, useEffect, useCallback } from 'react';
import { statisticsService } from '../services/statisticsService';
import { detectionService } from '../services/detectionService';
import { REFRESH_INTERVAL_MS } from '../utils/constants';

export const useStatistics = (autoRefresh = true) => {
  const [stats, setStats] = useState(null);
  const [trendData, setTrendData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [trendError, setTrendError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchStats = useCallback(async () => {
    setLoading(true);
    setError(null);
    setTrendError(null);
    try {
      const [statsResult, trendResult] = await Promise.allSettled([
        statisticsService.getStatistics(),
        detectionService.getDetectionTrend(24),
      ]);

      if (statsResult.status === 'fulfilled') {
        const statsRes = statsResult.value;
        const baseStats = statsRes.data?.data || statsRes.data || {};
        if (
          baseStats
          && typeof baseStats === 'object'
          && !Array.isArray(baseStats)
          && Number.isSafeInteger(baseStats.total_events)
        ) {
          setStats(baseStats);
        } else {
          setError('Statistics API returned an invalid response.');
        }
      } else {
        const err = statsResult.reason;
        setError(err.response?.data?.error?.message || err.message || 'Failed to load backend statistics');
      }

      if (trendResult.status === 'fulfilled') {
        const trendRes = trendResult.value;
        const responseData = trendRes.data?.data || trendRes.data || {};
        if (Array.isArray(responseData.trend)) {
          setTrendData(responseData.trend);
        } else {
          setTrendError('Detection trend API returned an invalid response.');
        }
      } else {
        const err = trendResult.reason;
        setTrendError(err.response?.data?.error?.message || err.message || 'Failed to load detection trend');
      }

      setLastUpdated(new Date());
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

  return {
    stats,
    trendData,
    loading,
    error,
    trendError,
    lastUpdated,
    refetch: fetchStats,
    refresh: fetchStats,
  };
};
