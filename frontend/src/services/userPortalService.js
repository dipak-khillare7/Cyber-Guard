import { detectionService } from './detectionService';
import { eventService } from './eventService';

const PAGE_SIZE = 100;
const MAX_PARALLEL_PAGES = 4;

const getPayload = (response) => response?.data?.data || response?.data || {};

async function getAllPages(fetchPage) {
  const firstPage = getPayload(await fetchPage({ skip: 0, limit: PAGE_SIZE }));
  const records = [...(firstPage.items || [])];
  const total = Number(firstPage.total) || records.length;

  for (let skip = PAGE_SIZE; skip < total; skip += PAGE_SIZE * MAX_PARALLEL_PAGES) {
    const offsets = Array.from(
      { length: Math.min(MAX_PARALLEL_PAGES, Math.ceil((total - skip) / PAGE_SIZE)) },
      (_, index) => skip + index * PAGE_SIZE,
    );
    const pages = await Promise.all(
      offsets.map((offset) => fetchPage({ skip: offset, limit: PAGE_SIZE })),
    );
    for (const response of pages) {
      records.push(...(getPayload(response).items || []));
    }
  }

  return records;
}

export const userPortalService = {
  async getActivity() {
    const [events, detections] = await Promise.all([
      getAllPages((params) => eventService.getEvents({ ...params, scope: 'own' })),
      getAllPages((params) => detectionService.getDetectionHistory({ ...params, scope: 'own' })),
    ]);

    const detectionsByEventId = new Map();
    for (const detection of detections) {
      const current = detectionsByEventId.get(detection.event_id);
      if (!current || (!current.alert_id && detection.alert_id)) {
        detectionsByEventId.set(detection.event_id, detection);
      }
    }

    const activity = events.map((event) => {
      const detection = detectionsByEventId.get(event.id);
      const hasAlert = Boolean(detection?.alert_id);
      return {
        ...event,
        event_id: event.id,
        timestamp: event.timestamp || event.created_at,
        detected_threat: hasAlert ? detection.detected_threat : detection ? 'NORMAL' : null,
        alert_id: hasAlert ? detection.alert_id : null,
        risk_level: hasAlert ? detection.risk_level : null,
        confidence: hasAlert ? detection.confidence : null,
        risk_score: null,
        message: hasAlert ? detection.message : null,
      };
    });

    return {
      events: activity.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)),
      total: events.length,
    };
  },
};
