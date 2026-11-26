const isCount = (value) => Number.isSafeInteger(value) && value >= 0;

export const getThreatDistributionChartData = (data) => {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return [];

  return Object.entries(data)
    .filter(([, count]) => isCount(count) && count > 0)
    .map(([key, count]) => ({
      name: String(key).replace(/_/g, ' ').toUpperCase(),
      rawKey: key,
      value: count,
    }));
};

export const getRiskSummaryChartData = (data) => {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return [];

  const knownLevels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const otherLevels = Object.keys(data)
    .filter((level) => !knownLevels.includes(level))
    .sort();

  return [...knownLevels, ...otherLevels]
    .filter((level) => isCount(data[level]) && data[level] > 0)
    .map((level) => ({
      level: level.replace(/_/g, ' '),
      rawLevel: level,
      count: data[level],
    }));
};

export const getDetectionTrendChartData = (data) => {
  if (!Array.isArray(data)) return [];

  return data
    .filter((bucket) => (
      bucket
      && typeof bucket.time === 'string'
      && bucket.time.trim().length > 0
      && isCount(bucket.threats)
      && isCount(bucket.normal)
    ))
    .map((bucket) => ({
      ...bucket,
      total: bucket.threats + bucket.normal,
    }));
};
