/**
 * Formats ISO timestamps into human-readable SOC format using Asia/Kolkata (IST).
 * Example: 2026-10-09T06:30:00Z -> 09 Oct 2026, 12:00:00 PM IST
 */
export const formatDate = (isoString) => {
  if (!isoString) return 'N/A';
  try {
    let dateStr = String(isoString).trim();
    // If input is a naive ISO string like "2026-10-09T06:30:00", treat as UTC by appending 'Z'
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(dateStr)) {
      dateStr += 'Z';
    }

    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return String(isoString);

    const formatter = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'Asia/Kolkata',
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    });

    const parts = formatter.formatToParts(d);
    let day = '', month = '', year = '', hour = '', minute = '', second = '', dayPeriod = '';

    for (const part of parts) {
      if (part.type === 'day') day = part.value;
      if (part.type === 'month') month = part.value;
      if (part.type === 'year') year = part.value;
      if (part.type === 'hour') hour = part.value;
      if (part.type === 'minute') minute = part.value;
      if (part.type === 'second') second = part.value;
      if (part.type === 'dayPeriod') dayPeriod = part.value.toUpperCase();
    }

    return `${day} ${month} ${year}, ${hour}:${minute}:${second} ${dayPeriod} IST`;
  } catch (err) {
    return String(isoString);
  }
};
