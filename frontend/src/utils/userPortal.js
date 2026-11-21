const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export function isValidIpAddress(value) {
  const address = value.trim();
  if (!address) return false;

  if (address.includes(':')) {
    try {
      return new URL(`http://[${address}]/`).hostname.startsWith('[');
    } catch {
      return false;
    }
  }

  const octets = address.split('.');
  return octets.length === 4 && octets.every((octet) => {
    if (!/^(0|[1-9]\d{0,2})$/.test(octet)) return false;
    const number = Number(octet);
    return number >= 0 && number <= 255;
  });
}

export function summarizeUserActivity(records) {
  const summary = {
    total: records.length,
    noAlert: 0,
    suspicious: 0,
    highRisk: 0,
    riskDistribution: Object.fromEntries(RISK_LEVELS.map((level) => [level, 0])),
  };

  for (const record of records) {
    if (!record.alert_id) {
      summary.noAlert += 1;
      continue;
    }

    summary.suspicious += 1;
    const risk = record.risk_level?.toUpperCase();
    if (risk in summary.riskDistribution) {
      summary.riskDistribution[risk] += 1;
    }
    if (risk === 'HIGH' || risk === 'CRITICAL') {
      summary.highRisk += 1;
    }
  }

  return summary;
}

export function filterAndSortUserHistory(records, filters) {
  const search = filters.search.trim().toLowerCase();
  return records
    .filter((record) => {
      const category = record.alert_id ? record.detected_threat : 'NO_ALERT';
      const risk = record.alert_id ? record.risk_level : 'NO_ALERT';
      const matchesSearch = !search || [
        record.event_id,
        record.source_ip,
        record.destination_ip,
        record.protocol,
        category,
      ].some((value) => String(value ?? '').toLowerCase().includes(search));
      return matchesSearch
        && (!filters.riskLevel || risk === filters.riskLevel)
        && (!filters.threatType || category === filters.threatType);
    })
    .sort((a, b) => {
      const difference = new Date(a.timestamp) - new Date(b.timestamp);
      return filters.sortOrder === 'oldest' ? difference : -difference;
    });
}

export function paginateRecords(records, page, pageSize) {
  const start = (page - 1) * pageSize;
  return records.slice(start, start + pageSize);
}
