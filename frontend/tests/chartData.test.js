import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getDetectionTrendChartData,
  getRiskSummaryChartData,
  getThreatDistributionChartData,
} from '../src/utils/chartData.js';

test('threat chart data keeps actual positive integer category counts only', () => {
  const data = getThreatDistributionChartData({
    DOS_DDOS: 3,
    NORMAL: 0,
    MALWARE: 2,
    INVALID: -1,
    UNKNOWN_VALUE: '4',
  });

  assert.deepEqual(data.map(({ name, value }) => ({ name, value })), [
    { name: 'DOS DDOS', value: 3 },
    { name: 'MALWARE', value: 2 },
  ]);
});

test('severity chart includes unknown backend categories and omits zero-only data', () => {
  assert.deepEqual(
    getRiskSummaryChartData({ LOW: 0, HIGH: 2, UNRECOGNIZED: 1 })
      .map(({ level, count }) => ({ level, count })),
    [
      { level: 'HIGH', count: 2 },
      { level: 'UNRECOGNIZED', count: 1 },
    ],
  );
  assert.deepEqual(getRiskSummaryChartData({ LOW: 0, HIGH: 0 }), []);
});

test('trend chart omits malformed buckets and derives totals from plotted series', () => {
  const data = getDetectionTrendChartData([
    { time: '26 Nov 2026 10:00', threats: 2, normal: 3, total: 99 },
    { time: 'invalid count', threats: '2', normal: 1 },
    { time: '', threats: 0, normal: 0 },
  ]);

  assert.deepEqual(data, [
    {
      time: '26 Nov 2026 10:00',
      threats: 2,
      normal: 3,
      total: 5,
    },
  ]);
});
