import assert from 'node:assert/strict';
import test from 'node:test';
import {
  filterAndSortUserHistory,
  isValidIpAddress,
  paginateRecords,
  summarizeUserActivity,
} from '../src/utils/userPortal.js';

test('validates IPv4 and IPv6 addresses without accepting malformed input', () => {
  assert.equal(isValidIpAddress('192.168.1.10'), true);
  assert.equal(isValidIpAddress('2001:db8::1'), true);
  assert.equal(isValidIpAddress('192.168.1.999'), false);
  assert.equal(isValidIpAddress('not-an-ip'), false);
});

test('summarizes alert-linked risks separately from events with no linked alert', () => {
  const summary = summarizeUserActivity([
    { event_id: 1, alert_id: null },
    { event_id: 2, alert_id: 12, risk_level: 'MEDIUM' },
    { event_id: 3, alert_id: 13, risk_level: 'CRITICAL' },
  ]);

  assert.equal(summary.total, 3);
  assert.equal(summary.noAlert, 1);
  assert.equal(summary.suspicious, 2);
  assert.equal(summary.highRisk, 1);
  assert.deepEqual(summary.riskDistribution, {
    LOW: 0,
    MEDIUM: 1,
    HIGH: 0,
    CRITICAL: 1,
  });
});

test('filters and sorts the full history collection and paginates filtered results', () => {
  const records = [
    { event_id: 1, timestamp: '2026-01-01T00:00:00Z', alert_id: null, source_ip: '10.0.0.1' },
    { event_id: 2, timestamp: '2026-01-03T00:00:00Z', alert_id: 8, risk_level: 'HIGH', detected_threat: 'BOTNET', source_ip: '10.0.0.2' },
    { event_id: 3, timestamp: '2026-01-02T00:00:00Z', alert_id: 9, risk_level: 'LOW', detected_threat: 'DOS_DDOS', source_ip: '10.0.0.3' },
  ];
  const filtered = filterAndSortUserHistory(records, {
    search: '10.0.0.',
    riskLevel: '',
    threatType: '',
    sortOrder: 'newest',
  });

  assert.deepEqual(filtered.map((record) => record.event_id), [2, 3, 1]);
  assert.deepEqual(
    paginateRecords(filtered, 2, 2).map((record) => record.event_id),
    [1],
  );
  assert.deepEqual(
    filterAndSortUserHistory(records, {
      search: '',
      riskLevel: 'HIGH',
      threatType: '',
      sortOrder: 'newest',
    }).map((record) => record.event_id),
    [2],
  );
});
